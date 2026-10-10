package main

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// outerKeyID returns the kid in a Service Token's readable JWE header.
func outerKeyID(t *testing.T, tok string) string {
	t.Helper()

	header, _, _ := strings.Cut(tok, ".")

	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("token header: %v", err)
	}

	var h struct {
		Kid string `json:"kid"`
	}

	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("token header: %v", err)
	}

	return h.Kid
}

// rotatedConfig writes a config file name in env.Dir with enc-next as the
// current encryption key and enc-e2e as a decryption key until retireAt.
func rotatedConfig(t *testing.T, env *servertest.Env, name string, retireAt time.Time) string {
	t.Helper()

	path := filepath.Join(env.Dir, name)

	servertest.WriteFile(t, path, `
listen: 127.0.0.1:0
tls:
  certFile: tls.crt
  keyFile: tls.key
keys:
  signingKeyFile: keys/sig-e2e.pem
  encryptionKeyFile: keys/enc-next.pem
  decryptionKeys:
    - keyFile: keys/enc-e2e.pem
      retireAt: `+retireAt.UTC().Format(time.RFC3339)+`
bootstrapSecretFile: bootstrap-secret
database:
  sqliteFile: dnsgate.db
`, 0o600)

	return path
}

func TestRotateThenResealEndToEnd(t *testing.T) {
	env := servertest.NewEnv(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	// Onboard under key A, enc-e2e.
	gwA := startServer(t, env.Config, provider.Registry())

	out, err := runClient(t, env, gwA, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	original := strings.TrimSpace(out)
	if kid := outerKeyID(t, original); kid != "enc-e2e" {
		t.Fatalf("original token kid = %q, want enc-e2e", kid)
	}

	want, err := runClient(t, env, gwA, "token", "inspect", "--token", original)
	if err != nil {
		t.Fatalf("token inspect: %v", err)
	}

	// Rotate to key B, enc-next, keeping A until its retirement deadline.
	servertest.GenerateKeys(t, env, "next")

	gwB := startServer(t, rotatedConfig(t, env, "rotated.yaml", time.Now().Add(24*time.Hour)), provider.Registry())

	if _, err := runClient(t, env, gwB, "token", "inspect", "--token", original); err != nil {
		t.Fatalf("original token after rotation: %v", err)
	}

	out, err = runClient(t, env, gwB, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard after rotation: %v", err)
	}

	if kid := outerKeyID(t, strings.TrimSpace(out)); kid != "enc-next" {
		t.Errorf("new token kid = %q, want enc-next", kid)
	}

	// Reseal the original token under B.
	out, err = runClient(t, env, gwB, "token", "reseal", original)
	if err != nil {
		t.Fatalf("token reseal: %v", err)
	}

	resealed := strings.TrimSpace(out)
	if resealed == "" || strings.ContainsAny(resealed, " \n") {
		t.Fatalf("token reseal printed %q, want the resealed token alone", out)
	}

	if kid := outerKeyID(t, resealed); kid != "enc-next" {
		t.Errorf("resealed token kid = %q, want enc-next", kid)
	}

	audit := gwB.Audit.String()
	if !strings.Contains(audit, `"event":"token.reseal"`) {
		t.Errorf("server audit output has no token.reseal event:\n%s", audit)
	}

	for _, secret := range []string{testCFToken, original, resealed} {
		if strings.Contains(audit, secret) || strings.Contains(gwB.Logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", audit, gwB.Logs.String())
		}
	}

	// Retire A: its deadline has passed.
	gwRetired := startServer(t, rotatedConfig(t, env, "retired.yaml", time.Now().Add(-time.Second)), provider.Registry())

	got, err := runClient(t, env, gwRetired, "token", "inspect", "--token", resealed)
	if err != nil {
		t.Fatalf("resealed token after A retired: %v", err)
	}

	if got != want {
		t.Errorf("resealed token inspects as\n%s\nwant the original\n%s", got, want)
	}

	if _, err := runClient(t, env, gwRetired, "token", "inspect", "--token", original); err == nil ||
		!strings.Contains(err.Error(), "unauthenticated") {
		t.Errorf("original token after A retired: error = %v, want unauthenticated", err)
	}
}

func TestTokenResealTakesTheTokenFromEnv(t *testing.T) {
	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config, provider.Registry())

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	t.Setenv("DNSGATE_TOKEN", strings.TrimSpace(out))

	out, err = runClient(t, env, gw, "token", "reseal")
	if err != nil {
		t.Fatalf("token reseal: %v", err)
	}

	if outerKeyID(t, strings.TrimSpace(out)) != "enc-e2e" {
		t.Errorf("token reseal printed %q, want a token sealed under enc-e2e", out)
	}

	t.Setenv("DNSGATE_TOKEN", "")

	if _, err := runClient(t, env, gw, "token", "reseal"); err == nil || !strings.Contains(err.Error(), "no Service Token") {
		t.Errorf("token reseal without a token: error = %v, want no Service Token", err)
	}
}
