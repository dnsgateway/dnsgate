package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const appPermissionsYAML = `permissions:
  - verbs: [get, list]
    zones: [example.com]
    names: ["**.apps"]
    types: [A]
    egress: [gateway]
`

func TestCreateADerivedTokenEndToEnd(t *testing.T) {
	useFakeProvider(t)

	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	root := strings.TrimSpace(out)
	t.Setenv("DNSGATE_TOKEN", root)

	perms := filepath.Join(t.TempDir(), "app.yaml")
	writeFile(t, perms, appPermissionsYAML, 0o600)

	out, err = runClient(t, env, gw, "token", "create", "--sub", "external-dns-prod", "--permissions", perms, "--expires", "24h")
	if err != nil {
		t.Fatalf("token create: %v", err)
	}

	derived := strings.TrimSpace(out)
	if derived == "" || strings.ContainsAny(derived, " \n") || derived == root {
		t.Fatalf("token create printed %q, want the Derived Token alone", out)
	}

	out, err = runClient(t, env, gw, "token", "inspect", "--token", derived)
	if err != nil {
		t.Fatalf("token inspect: %v", err)
	}

	var got inspected
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("inspect output is not JSON: %v\n%s", err, out)
	}

	if got.Sub != "external-dns-prod" || len(got.Ancestors) != 1 || got.Expiry == nil || !got.Expiry.Equal(got.IssuedAt.Add(24*time.Hour)) {
		t.Errorf("inspected sub, ancestors, exp = %q, %v, %v", got.Sub, got.Ancestors, got.Expiry)
	}

	if len(got.Permissions) != 1 || !slices.Equal(got.Permissions[0].Names, []string{"**.apps"}) || got.Permissions[0].Resources != nil {
		t.Errorf("inspected permissions = %+v, want the file's", got.Permissions)
	}

	t.Setenv("DNSGATE_TOKEN", derived)
	t.Setenv("DNSGATE_ZONE", "example.com")

	if _, err := runClient(t, env, gw, "record", "get", "www.apps", "A"); err != nil {
		t.Errorf("record get within the Permissions: %v", err)
	}

	if _, err := runClient(t, env, gw, "record", "get", "www.apps", "TXT"); err == nil {
		t.Error("record get outside the Permissions succeeded")
	}

	// The Derived Token holds no create on tokens.
	if _, err := runClient(t, env, gw, "token", "create", "--sub", "other", "--permissions", perms); err == nil {
		t.Error("a token without create on tokens issued one")
	}

	audit := gw.audit.String()
	if !strings.Contains(audit, `"event":"token.create"`) || !strings.Contains(audit, `"jti":"`+got.Jti+`"`) ||
		!strings.Contains(audit, `"parent_jti":"`+got.Ancestors[0]+`"`) {
		t.Errorf("server audit output has no token.create event for %s:\n%s", got.Jti, audit)
	}

	for _, secret := range []string{testCFToken, testBootstrapSecret, root, derived} {
		if strings.Contains(audit, secret) || strings.Contains(gw.logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", audit, gw.logs.String())
		}
	}
}

func TestTokenCreateTakesAJSONPermissionsFileLikeAYAMLOne(t *testing.T) {
	useFakeProvider(t)

	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	t.Setenv("DNSGATE_TOKEN", strings.TrimSpace(out))

	dir := t.TempDir()

	files := map[string]string{
		"app.yaml": `permissions:
  - verbs: [get, list, create]
    zones: [example.com]
    names: ["*.apps", "_acme-challenge.**"]
    types: [A, TXT]
    egress: [gateway]
  - verbs: [list]
    resources: [zones]
`,
		"app.json": `{
  "permissions": [
    {
      "verbs": ["get", "list", "create"],
      "zones": ["example.com"],
      "names": ["*.apps", "_acme-challenge.**"],
      "types": ["A", "TXT"],
      "egress": ["gateway"]
    },
    {"verbs": ["list"], "resources": ["zones"]}
  ]
}
`,
	}

	// permissions are the Derived Token Permissions issued from each file.
	permissions := map[string][]inspectedPermission{}

	for name, content := range files {
		path := filepath.Join(dir, name)
		writeFile(t, path, content, 0o600)

		out, err := runClient(t, env, gw, "token", "create", "--sub", "app", "--permissions", path)
		if err != nil {
			t.Fatalf("token create with %s: %v", name, err)
		}

		out, err = runClient(t, env, gw, "token", "inspect", "--token", strings.TrimSpace(out))
		if err != nil {
			t.Fatalf("token inspect of the token from %s: %v", name, err)
		}

		var got inspected
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("inspect output is not JSON: %v\n%s", err, out)
		}

		permissions[name] = got.Permissions
	}

	fromYAML := permissions["app.yaml"]
	if len(fromYAML) != 2 || !slices.Equal(fromYAML[1].Resources, []string{"zones"}) {
		t.Fatalf("Derived Token Permissions from app.yaml = %+v, want its two, the second on zones", fromYAML)
	}

	if fromJSON := permissions["app.json"]; !reflect.DeepEqual(fromJSON, fromYAML) {
		t.Errorf("Derived Token Permissions from app.json =\n%+v\nwant those from app.yaml\n%+v", fromJSON, fromYAML)
	}
}

func TestTheConfigLimitsTheChainDepth(t *testing.T) {
	useFakeProvider(t)

	env := newGatewayEnv(t)

	config, err := os.ReadFile(env.config)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, env.config, string(config)+"tokens:\n  maxAncestors: 1\n", 0o600)

	gw := startServer(t, env.config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	issuer := filepath.Join(t.TempDir(), "issuer.yaml")
	writeFile(t, issuer, "permissions:\n  - verbs: [create]\n    resources: [tokens]\n", 0o600)

	t.Setenv("DNSGATE_TOKEN", strings.TrimSpace(out))

	out, err = runClient(t, env, gw, "token", "create", "--sub", "intermediate", "--permissions", issuer)
	if err != nil {
		t.Fatalf("token create below the Root Token: %v", err)
	}

	t.Setenv("DNSGATE_TOKEN", strings.TrimSpace(out))

	if _, err := runClient(t, env, gw, "token", "create", "--sub", "app", "--permissions", issuer); err == nil {
		t.Error("a token with one ancestor issued one, with maxAncestors 1")
	}
}

func TestTokenCreateChecksItsFlagsAndFile(t *testing.T) {
	dir := t.TempDir()
	file := func(name, data string) string {
		path := filepath.Join(dir, name)
		writeFile(t, path, data, 0o600)

		return path
	}

	good := file("good.yaml", appPermissionsYAML)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no token":        {[]string{"--token", "", "--sub", "app", "--permissions", good}, "no Parent Token"},
		"no sub":          {[]string{"--permissions", good}, "--sub"},
		"no permissions":  {[]string{"--sub", "app"}, "--permissions"},
		"missing file":    {[]string{"--sub", "app", "--permissions", filepath.Join(dir, "none.yaml")}, "reading permissions"},
		"not YAML":        {[]string{"--sub", "app", "--permissions", file("bad.yaml", "permissions: [")}, "permissions file"},
		"unknown field":   {[]string{"--sub", "app", "--permissions", file("field.yaml", "permissions:\n  - verbs: [get]\n    zone: [example.com]\n")}, "permissions file"},
		"no rules":        {[]string{"--sub", "app", "--permissions", file("empty.yaml", "permissions: []\n")}, "no permissions"},
		"rule, no verbs":  {[]string{"--sub", "app", "--permissions", file("noverbs.yaml", "permissions:\n  - zones: [example.com]\n")}, "verbs"},
		"negative expiry": {[]string{"--sub", "app", "--permissions", good, "--expires", "-1h"}, "--expires"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DNSGATE_TOKEN", "a-token")

			cmd := newRootCmd()
			cmd.SetOut(&strings.Builder{})
			cmd.SetErr(&strings.Builder{})
			cmd.SetArgs(append([]string{"token", "create", "--gateway", "127.0.0.1:1"}, tc.args...))

			err := cmd.ExecuteContext(t.Context())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}
