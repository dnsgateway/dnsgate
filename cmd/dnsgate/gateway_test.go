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
// bootstrap secret and config file in a temporary directory, and the
// address its config listens on.
type gatewayEnv struct {
	dir    string
	config string
	caFile string
	listen string
}

// newGatewayEnv configures a Gateway that listens on an ephemeral port,
// which it logs once it serves.
func newGatewayEnv(t *testing.T) *gatewayEnv {
	t.Helper()

	return newGatewayEnvAt(t, "127.0.0.1:0")
}

// newGatewayEnvAt configures a Gateway that listens on listen.
func newGatewayEnvAt(t *testing.T, listen string) *gatewayEnv {
	t.Helper()

	dir := t.TempDir()
	env := &gatewayEnv{dir: dir, config: filepath.Join(dir, "dnsgate.yaml"), caFile: filepath.Join(dir, "tls.crt"), listen: listen}

	if out, err := runCLI(t, "keys", "generate", "--key-dir", filepath.Join(dir, "keys"), "--key-id-suffix", "e2e"); err != nil {
		t.Fatalf("keys generate: %v\n%s", err, out)
	}

	writeTLSCert(t, env.caFile, filepath.Join(dir, "tls.key"))
	writeFile(t, filepath.Join(dir, "bootstrap-secret"), testBootstrapSecret+"\n", 0o600)

	// Relative paths are resolved against the config file's directory.
	writeFile(t, env.config, `
listen: `+env.listen+`
tls:
  certFile: tls.crt
  keyFile: tls.key
keys:
  signingKeyFile: keys/sig-e2e.pem
  encryptionKeyFile: keys/enc-e2e.pem
bootstrapSecretFile: bootstrap-secret
database:
  sqliteFile: dnsgate.db
`, 0o600)

	return env
}

// writeDecryptionKeysConfig rewrites env's config file with entries as
// its keys.decryptionKeys list.
func writeDecryptionKeysConfig(t *testing.T, env *gatewayEnv, entries string) {
	t.Helper()

	writeFile(t, env.config, `
listen: `+env.listen+`
tls:
  certFile: tls.crt
  keyFile: tls.key
keys:
  signingKeyFile: keys/sig-e2e.pem
  encryptionKeyFile: keys/enc-e2e.pem
  decryptionKeys:
`+entries+`bootstrapSecretFile: bootstrap-secret
database:
  sqliteFile: dnsgate.db
`, 0o600)
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

// writeUnrelatedCAFile writes a self-signed certificate that does not sign
// the Gateway's certificate and returns its path.
func writeUnrelatedCAFile(t *testing.T) string {
	t.Helper()

	certFile := filepath.Join(t.TempDir(), "other.crt")
	writeTLSCert(t, certFile, filepath.Join(t.TempDir(), "other.key"))

	return certFile
}

// runningGateway is a "dnsgate server" running in the test process.
type runningGateway struct {
	addr  string
	audit *syncBuffer
	logs  *syncBuffer
}

var listenAddr = regexp.MustCompile(`"address":"([^"]+)"`)

// startServer runs "dnsgate server --config" with args until the test ends
// and waits for it to log its listen address.
func startServer(t *testing.T, config string, args ...string) *runningGateway {
	t.Helper()

	return launchServer(t, config, args, func(gw *runningGateway) bool {
		m := listenAddr.FindStringSubmatch(gw.logs.String())
		if m == nil {
			return false
		}

		gw.addr = m[1]

		return true
	})
}

// freePort returns a local address no one listens on, for a Gateway
// whose logs do not tell its address.
func freePort(t *testing.T) string {
	t.Helper()

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := lis.Addr().String()
	_ = lis.Close()

	return addr
}

// startServerAt runs "dnsgate server --config" for env with args until the
// test ends and waits for it to accept connections at env's listen address.
// It does not rely on the server's logs.
func startServerAt(t *testing.T, env *gatewayEnv, args ...string) *runningGateway {
	t.Helper()

	addr := env.listen

	return launchServer(t, env.config, args, func(gw *runningGateway) bool {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return false
		}

		_ = conn.Close()
		gw.addr = addr

		return true
	})
}

// launchServer runs "dnsgate server --config" with args until the test ends
// and waits until ready reports it is serving.
func launchServer(t *testing.T, config string, args []string, ready func(*runningGateway) bool) *runningGateway {
	t.Helper()

	gw := &runningGateway{audit: &syncBuffer{}, logs: &syncBuffer{}}

	cmd := newRootCmd()
	cmd.SetOut(gw.audit)
	cmd.SetErr(gw.logs)
	cmd.SetArgs(append([]string{"server", "--config", config}, args...))

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
		if ready(gw) {
			return gw
		}

		select {
		case err := <-done:
			done <- err
			t.Fatalf("server exited: %v\n%s", err, gw.logs.String())
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Fatalf("server is not serving:\n%s", gw.logs.String())

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

func TestOnboardTrustsEveryRepeatedCAFile(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)
	other := writeUnrelatedCAFile(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	// The Gateway's CA comes last, so it is trusted only if every file is pooled.
	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.addr,
		"--ca-file", other, "--ca-file", env.caFile)
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, out)
	}
}

func TestOnboardTakesTheCAFilesFromEnvAsAPathList(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)
	other := writeUnrelatedCAFile(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)
	t.Setenv("DNSGATE_CA_FILE", other+string(os.PathListSeparator)+env.caFile)

	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.addr)
	if err != nil {
		t.Fatalf("onboard: %v\n%s", err, out)
	}
}

func TestOnboardCAFileFlagReplacesTheEnvPathList(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)
	other := writeUnrelatedCAFile(t)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)
	t.Setenv("DNSGATE_CA_FILE", env.caFile)

	// --ca-file replaces DNSGATE_CA_FILE, so the Gateway's CA is not trusted.
	out, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.addr,
		"--ca-file", other)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("onboard error = %v, want a certificate error\n%s", err, out)
	}

	if audit := gw.audit.String(); audit != "" {
		t.Errorf("the Gateway saw a request:\n%s", audit)
	}
}

func TestOnboardRefusesACAFileWithNoCertificate(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	empty := filepath.Join(t.TempDir(), "empty.crt")
	writeFile(t, empty, "no certificate here", 0o644)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	_, err := runCLI(t, "onboard", "--provider", "cloudflare", "--gateway", gw.addr,
		"--ca-file", env.caFile, "--ca-file", empty)
	if err == nil || !strings.Contains(err.Error(), empty) {
		t.Errorf("onboard error = %v, want one naming %s", err, empty)
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
		"decryption key without retireAt": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeDecryptionKeysConfig(t, env, "    - keyFile: keys/enc-old.pem\n")
			},
			want: "keys.decryptionKeys[0].retireAt is required",
		},
		"decryption key without keyFile": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeDecryptionKeysConfig(t, env, "    - retireAt: 2030-01-01T00:00:00Z\n")
			},
			want: "keys.decryptionKeys[0].keyFile is required",
		},
		"decryption key with a malformed retireAt": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeDecryptionKeysConfig(t, env, "    - keyFile: keys/enc-old.pem\n      retireAt: next month\n")
			},
			want: "parsing config",
		},
		"decryption key with an unknown field": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeDecryptionKeysConfig(t, env, "    - keyFile: keys/enc-old.pem\n      retireAt: 2030-01-01T00:00:00Z\n      retireAfter: 720h\n")
			},
			want: "retireAfter",
		},
		"decryption key that is the current key": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeDecryptionKeysConfig(t, env, "    - keyFile: keys/enc-e2e.pem\n      retireAt: 2030-01-01T00:00:00Z\n")
			},
			want: "used twice",
		},
		"missing decryption key file": {
			edit: func(t *testing.T, env *gatewayEnv) {
				writeDecryptionKeysConfig(t, env, "    - keyFile: keys/enc-old.pem\n      retireAt: 2030-01-01T00:00:00Z\n")
			},
			want: "enc-old.pem",
		},
		"negative maxAncestors": {
			edit: func(t *testing.T, env *gatewayEnv) {
				config, err := os.ReadFile(env.config)
				if err != nil {
					t.Fatal(err)
				}

				writeFile(t, env.config, string(config)+"tokens:\n  maxAncestors: -1\n", 0o600)
			},
			want: "tokens.maxAncestors",
		},
		"missing database file setting": {
			edit: func(t *testing.T, env *gatewayEnv) {
				config, err := os.ReadFile(env.config)
				if err != nil {
					t.Fatal(err)
				}

				writeFile(t, env.config, strings.Replace(string(config), "database:\n  sqliteFile: dnsgate.db\n", "", 1), 0o600)
			},
			want: "database.sqliteFile is required",
		},
		"database file in a missing directory": {
			edit: func(t *testing.T, env *gatewayEnv) {
				config, err := os.ReadFile(env.config)
				if err != nil {
					t.Fatal(err)
				}

				writeFile(t, env.config, strings.Replace(string(config), "sqliteFile: dnsgate.db", "sqliteFile: missing/dnsgate.db", 1), 0o600)
			},
			want: "revocation database",
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
