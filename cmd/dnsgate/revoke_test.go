package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

const adminPermissionsYAML = `permissions:
  - verbs: [create, delete]
    resources: [tokens]
  - verbs: [get, list]
`

// onboardAndIssue onboards against gw and issues, under the Root Token,
// one Derived Token per Service Account in subs, with the Permissions in
// perms. It returns the Root Token and the Derived Tokens.
func onboardAndIssue(t *testing.T, env *gatewayEnv, gw *runningGateway, perms string, subs ...string) (string, []string) {
	t.Helper()

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	root := strings.TrimSpace(out)

	file := filepath.Join(t.TempDir(), "perms.yaml")
	writeFile(t, file, perms, 0o600)

	tokens := make([]string, 0, len(subs))

	for _, sub := range subs {
		out, err := runClient(t, env, gw, "token", "create", "--token", root, "--sub", sub, "--permissions", file, "--expires", "1h")
		if err != nil {
			t.Fatalf("token create: %v", err)
		}

		tokens = append(tokens, strings.TrimSpace(out))
	}

	return root, tokens
}

// jti returns the ID of tok, as "token inspect" shows it.
func jti(t *testing.T, env *gatewayEnv, gw *runningGateway, tok string) string {
	t.Helper()

	out, err := runClient(t, env, gw, "token", "inspect", "--token", tok)
	if err != nil {
		t.Fatalf("token inspect: %v", err)
	}

	_, rest, _ := strings.Cut(out, `"jti": "`)
	id, _, _ := strings.Cut(rest, `"`)

	return id
}

func TestRevokeByIDAndByTokenEndToEnd(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	root, tokens := onboardAndIssue(t, env, gw, adminPermissionsYAML, "by-id", "by-token", "by-stdin", "kept")
	byID, byToken, byStdin, kept := tokens[0], tokens[1], tokens[2], tokens[3]
	byIDJti := jti(t, env, gw, byID)

	t.Setenv("DNSGATE_TOKEN", root)

	out, err := runClient(t, env, gw, "token", "revoke", byIDJti)
	if err != nil {
		t.Fatalf("token revoke ID: %v", err)
	}

	if strings.TrimSpace(out) != byIDJti {
		t.Errorf("token revoke printed %q, want the revoked ID %s", out, byIDJti)
	}

	if _, err := runClient(t, env, gw, "token", "revoke", byToken); err != nil {
		t.Fatalf("token revoke TOKEN: %v", err)
	}

	// "-" reads the token to revoke from stdin, out of process listings.
	cmd := newRootCmd()
	cmd.SetIn(strings.NewReader(byStdin + "\n"))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"token", "revoke", "-", "--gateway", gw.addr, "--ca-file", env.caFile})

	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("token revoke -: %v", err)
	}

	// The Gateway restarts on the same database.
	gw2 := startServer(t, env.config)

	for name, tok := range map[string]string{"by-id": byID, "by-token": byToken, "by-stdin": byStdin} {
		_, err := runClient(t, env, gw2, "token", "inspect", "--token", tok)
		if err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Errorf("%s after a restart: inspect error = %v, want a revoked token", name, err)
		}
	}

	if _, err := runClient(t, env, gw2, "token", "inspect", "--token", kept); err != nil {
		t.Errorf("a token that was not revoked: %v", err)
	}

	audit := gw.audit.String()
	if strings.Count(audit, `"event":"token.revoke"`) != 3 || !strings.Contains(audit, `"revoked_jti":"`+byIDJti+`"`) {
		t.Errorf("server audit output does not have the three token.revoke events:\n%s", audit)
	}

	for _, secret := range []string{testCFToken, root, byToken, byStdin} {
		if strings.Contains(audit, secret) || strings.Contains(gw.logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", audit, gw.logs.String())
		}
	}
}

func TestRevokeIsDeniedWithoutDeleteOnTokens(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	_, tokens := onboardAndIssue(t, env, gw, "permissions:\n  - verbs: [create]\n    resources: [tokens]\n", "issuer", "target")

	t.Setenv("DNSGATE_TOKEN", tokens[0])

	_, err := runClient(t, env, gw, "token", "revoke", jti(t, env, gw, tokens[1]))
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("token revoke error = %v, want permission denied", err)
	}

	if audit := gw.audit.String(); !strings.Contains(audit, `"event":"token.revoke"`) || !strings.Contains(audit, `"result":"denied"`) {
		t.Errorf("server audit output has no denied token.revoke event:\n%s", audit)
	}
}

func TestTokenRevokeChecksItsArguments(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no token":       {[]string{"token", "revoke", "tok_01ARZ3NDEKTSV4RRFFQ69G5FAV", "--token", ""}, "no Service Token"},
		"no target":      {[]string{"token", "revoke"}, "accepts 1 arg"},
		"two targets":    {[]string{"token", "revoke", "a", "b"}, "accepts 1 arg"},
		"empty stdin":    {[]string{"token", "revoke", "-"}, "no token to revoke on stdin"},
		"empty argument": {[]string{"token", "revoke", ""}, "no token to revoke"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DNSGATE_TOKEN", "a-token")

			cmd := newRootCmd()
			cmd.SetIn(strings.NewReader(""))
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})
			cmd.SetArgs(append(tc.args, "--gateway", "127.0.0.1:1"))

			err := cmd.ExecuteContext(t.Context())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}
