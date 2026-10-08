package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testBootstrapSecret = "e2e-bootstrap-secret-0123456789"
	testCFToken         = "cf-api-token-E2E-SECRET"
)

// syncBuffer is a bytes.Buffer safe to write from the server's goroutines
// while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// gatewayEnv is a configured Gateway: its key files, TLS certificate,
// bootstrap secret and config file in a temporary directory.
type gatewayEnv struct {
	dir    string
	config string
	caFile string
}

func newGatewayEnv(t *testing.T) *gatewayEnv {
	t.Helper()

	dir := t.TempDir()
	env := &gatewayEnv{dir: dir, config: filepath.Join(dir, "dnsgate.yaml"), caFile: filepath.Join(dir, "tls.crt")}

	if out, err := runCLI(t, "keys", "generate", "--key-dir", filepath.Join(dir, "keys"), "--key-id-suffix", "e2e"); err != nil {
		t.Fatalf("keys generate: %v\n%s", err, out)
	}

	writeTLSCert(t, env.caFile, filepath.Join(dir, "tls.key"))
	writeFile(t, filepath.Join(dir, "bootstrap-secret"), testBootstrapSecret+"\n", 0o600)

	// Relative paths are resolved against the config file's directory.
	writeFile(t, env.config, `
listen: 127.0.0.1:0
tls:
  certFile: tls.crt
  keyFile: tls.key
keys:
  signingKeyFile: keys/sig-e2e.pem
  encryptionKeyFile: keys/enc-e2e.pem
bootstrapSecretFile: bootstrap-secret
`, 0o600)

	return env
}

func writeFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

// writeTLSCert writes a self-signed certificate for 127.0.0.1 and its key.
func writeTLSCert(t *testing.T, certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dnsgate test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), 0o600)
}

// runningGateway is a "dnsgate server" running in the test process.
type runningGateway struct {
	addr  string
	audit *syncBuffer
	logs  *syncBuffer
}

var listenAddr = regexp.MustCompile(`"address":"([^"]+)"`)

// startServer runs "dnsgate server --config" until the test ends and waits
// for it to log its listen address.
func startServer(t *testing.T, config string) *runningGateway {
	t.Helper()

	gw := &runningGateway{audit: &syncBuffer{}, logs: &syncBuffer{}}

	cmd := newRootCmd()
	cmd.SetOut(gw.audit)
	cmd.SetErr(gw.logs)
	cmd.SetArgs([]string{"server", "--config", config})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- cmd.ExecuteContext(ctx) }()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil {
			t.Errorf("server: %v", err)
		}
	})

	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		if m := listenAddr.FindStringSubmatch(gw.logs.String()); m != nil {
			gw.addr = m[1]

			return gw
		}

		select {
		case err := <-done:
			done <- err
			t.Fatalf("server exited: %v\n%s", err, gw.logs.String())
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Fatalf("server did not log its address:\n%s", gw.logs.String())

	return nil
}

// runClient runs a client command against gw, returning stdout and the
// error; stderr is discarded.
func runClient(t *testing.T, env *gatewayEnv, gw *runningGateway, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(append(args, "--gateway", gw.addr, "--ca-file", env.caFile))

	err := cmd.ExecuteContext(t.Context())

	return out.String(), err
}

type inspected struct {
	Sub         string     `json:"sub"`
	Jti         string     `json:"jti"`
	Ancestors   []string   `json:"ancestors"`
	IssuedAt    time.Time  `json:"iat"`
	NotBefore   time.Time  `json:"nbf"`
	Expiry      *time.Time `json:"exp"`
	Provider    string     `json:"provider"`
	Permissions []struct {
		Verbs     []string `json:"verbs"`
		Resources []string `json:"resources"`
		Zones     []string `json:"zones"`
		Names     []string `json:"names"`
		Types     []string `json:"types"`
		Egress    []string `json:"egress"`
	} `json:"permissions"`
}

func TestOnboardThenInspectEndToEnd(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

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

	audit := gw.audit.String()
	if !strings.Contains(audit, `"event":"onboard"`) || !strings.Contains(audit, `"jti":"`+got.Jti+`"`) {
		t.Errorf("server audit output has no onboard event for %s:\n%s", got.Jti, audit)
	}

	for _, secret := range []string{testCFToken, testBootstrapSecret, root} {
		if strings.Contains(audit, secret) || strings.Contains(gw.logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", audit, gw.logs.String())
		}
	}
}

func TestOnboardFailsWithWrongOrMissingBootstrapSecret(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

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
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	// Without --ca-file the self-signed Gateway certificate is not trusted.
	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.addr)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("onboard error = %v, want a certificate error\n%s", err, out)
	}

	if audit := gw.audit.String(); audit != "" {
		t.Errorf("the Gateway saw a request:\n%s", audit)
	}
}

func TestServerRefusesToStartWithBadConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(t *testing.T, env *gatewayEnv)
		want string
	}{
		"missing config file": {
			edit: func(t *testing.T, env *gatewayEnv) { env.config = filepath.Join(env.dir, "missing.yaml") },
			want: "reading config",
		},
		"unknown field": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeFile(t, env.config, "listen: 127.0.0.1:0\nbootstrapSecret: inline\n", 0o600)
			},
			want: "bootstrapSecret",
		},
		"missing setting": {
			edit: func(t *testing.T, env *gatewayEnv) { writeFile(t, env.config, "listen: 127.0.0.1:0\n", 0o600) },
			want: "is required",
		},
		"missing key file": {
			edit: func(t *testing.T, env *gatewayEnv) {
				if err := os.Remove(filepath.Join(env.dir, "keys", "enc-e2e.pem")); err != nil {
					t.Fatal(err)
				}
			},
			want: "enc-e2e.pem",
		},
		"loose bootstrap secret file": {
			edit: func(t *testing.T, env *gatewayEnv) {
				if err := os.Chmod(filepath.Join(env.dir, "bootstrap-secret"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "bootstrap secret file",
		},
		"short bootstrap secret": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeFile(t, filepath.Join(env.dir, "bootstrap-secret"), "short\n", 0o600)
			},
			want: "fewer than 16 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := newGatewayEnv(t)
			tc.edit(t, env)

			out, err := runCLI(t, "server", "--config", env.config)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("server error = %v, want one containing %q\n%s", err, tc.want, out)
			}
		})
	}
}

func TestServerTakesConfigFromEnv(t *testing.T) {
	env := newGatewayEnv(t)
	t.Setenv("DNSGATE_CONFIG", filepath.Join(env.dir, "missing.yaml"))

	if _, err := runCLI(t, "server"); err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Errorf("server error = %v, want one naming the config file from DNSGATE_CONFIG", err)
	}
}
