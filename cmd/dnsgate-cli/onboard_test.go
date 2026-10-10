package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

type inspected struct {
	Sub         string                `json:"sub"`
	Jti         string                `json:"jti"`
	Ancestors   []string              `json:"ancestors"`
	IssuedAt    time.Time             `json:"iat"`
	NotBefore   time.Time             `json:"nbf"`
	Expiry      *time.Time            `json:"exp"`
	Provider    string                `json:"provider"`
	Permissions []inspectedPermission `json:"permissions"`
}

// inspectedPermission is one Permission of an inspected token.
type inspectedPermission struct {
	Verbs     []string `json:"verbs"`
	Resources []string `json:"resources"`
	Zones     []string `json:"zones"`
	Names     []string `json:"names"`
	Types     []string `json:"types"`
	Egress    []string `json:"egress"`
}

func TestOnboardThenInspectEndToEnd(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	before := time.Now().Truncate(time.Second)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare", "--expires", "24h")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	root := strings.TrimSpace(out)
	if root == "" || strings.ContainsAny(root, " \n") {
		t.Fatalf("onboard printed %q, want the Root Token alone", out)
	}

	out, err = runClient(t, env, gw, "token", "inspect", "--token", root)
	if err != nil {
		t.Fatalf("token inspect: %v", err)
	}

	if strings.Contains(out, testCFToken) {
		t.Errorf("inspect output shows the Provider Credential:\n%s", out)
	}

	var got inspected
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("inspect output is not JSON: %v\n%s", err, out)
	}

	if got.Sub != "root" || !strings.HasPrefix(got.Jti, "tok_") || got.Provider != "cloudflare" || len(got.Ancestors) != 0 {
		t.Errorf("inspected sub, jti, provider, ancestors = %q, %q, %q, %v", got.Sub, got.Jti, got.Provider, got.Ancestors)
	}

	if got.IssuedAt.Before(before) || got.Expiry == nil || !got.Expiry.Equal(got.IssuedAt.Add(24*time.Hour)) {
		t.Errorf("inspected iat, exp = %v, %v, want exp 24h after iat", got.IssuedAt, got.Expiry)
	}

	if len(got.Permissions) != 1 {
		t.Fatalf("inspected permissions = %+v, want one", got.Permissions)
	}

	p := got.Permissions[0]
	if !slices.Equal(p.Verbs, []string{"get", "list", "create", "update", "patch", "delete"}) ||
		!slices.Equal(p.Resources, []string{"zones", "records", "tokens"}) ||
		!slices.Equal(p.Zones, []string{"*"}) || !slices.Equal(p.Names, []string{"@", "**"}) ||
		!slices.Equal(p.Types, []string{"*"}) || !slices.Equal(p.Egress, []string{"gateway", "agent"}) {
		t.Errorf("inspected permission = %+v, want the full Root Token permission", p)
	}

	audit := gw.Audit.String()
	if !strings.Contains(audit, `"event":"onboard"`) || !strings.Contains(audit, `"jti":"`+got.Jti+`"`) {
		t.Errorf("server audit output has no onboard event for %s:\n%s", got.Jti, audit)
	}

	for _, secret := range []string{testCFToken, testBootstrapSecret, root} {
		if strings.Contains(audit, secret) || strings.Contains(gw.Logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", audit, gw.Logs.String())
		}
	}
}

func TestOnboardFailsWithWrongOrMissingBootstrapSecret(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)

	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	for name, tc := range map[string]struct {
		secret string
		want   string
	}{
		"wrong":   {"not-the-bootstrap-secret", "unauthenticated: wrong or missing bootstrap secret"},
		"missing": {"", "no bootstrap secret"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DNSGATE_BOOTSTRAP_SECRET", tc.secret)

			out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("onboard error = %v, want one containing %q", err, tc.want)
			}

			if out != "" {
				t.Errorf("onboard printed %q, want nothing", out)
			}
		})
	}
}

func TestOnboardRefusesAnUnverifiedGateway(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	// Without --ca-file the self-signed Gateway certificate is not trusted.
	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.Addr)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("onboard error = %v, want a certificate error\n%s", err, out)
	}

	if audit := gw.Audit.String(); audit != "" {
		t.Errorf("the Gateway saw a request:\n%s", audit)
	}
}

func TestOnboardTrustsEveryRepeatedCAFile(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)
	other := writeUnrelatedCAFile(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	// The Gateway's CA comes last, so it is trusted only if every file is pooled.
	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.Addr,
		"--ca-file", other, "--ca-file", env.CAFile)
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, out)
	}
}

func TestOnboardTakesTheCAFilesFromEnvAsAPathList(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)
	other := writeUnrelatedCAFile(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)
	t.Setenv("DNSGATE_CA_FILE", other+string(os.PathListSeparator)+env.CAFile)

	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.Addr)
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, out)
	}
}

func TestOnboardCAFileFlagReplacesTheEnvPathList(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)
	other := writeUnrelatedCAFile(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)
	t.Setenv("DNSGATE_CA_FILE", env.CAFile)

	// --ca-file replaces DNSGATE_CA_FILE, so the Gateway's CA is not trusted.
	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.Addr,
		"--ca-file", other)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("onboard error = %v, want a certificate error\n%s", err, out)
	}

	if audit := gw.Audit.String(); audit != "" {
		t.Errorf("the Gateway saw a request:\n%s", audit)
	}
}

func TestOnboardRefusesACAFileWithNoCertificate(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config)

	empty := filepath.Join(t.TempDir(), "empty.crt")
	servertest.WriteFile(t, empty, "no certificate here", 0o644)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	_, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.Addr,
		"--ca-file", env.CAFile, "--ca-file", empty)
	if err == nil || !strings.Contains(err.Error(), empty) {
		t.Errorf("onboard error = %v, want one naming %s", err, empty)
	}
}
