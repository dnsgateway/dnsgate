// Package servertest configures and runs Gateways in the test process,
// for the end-to-end tests of the dnsgate and dnsgate-cli commands.
package servertest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"

	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/server"
)

// BootstrapSecret is the bootstrap secret of the Gateways NewEnv
// configures.
const BootstrapSecret = "e2e-bootstrap-secret-0123456789"

// SyncBuffer is a bytes.Buffer safe to write from the Gateway's goroutines
// while the test reads it.
type SyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *SyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *SyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

// Env is a configured Gateway: its key files, TLS certificate, bootstrap
// secret and config file in a temporary directory, and the address its
// config listens on.
type Env struct {
	Dir    string
	Config string
	CAFile string
	Listen string
}

// NewEnv configures a Gateway that listens on an ephemeral port, which it
// logs once it serves.
func NewEnv(t *testing.T) *Env {
	t.Helper()

	return NewEnvAt(t, "127.0.0.1:0")
}

// NewEnvAt configures a Gateway that listens on listen, with the key IDs
// sig-e2e and enc-e2e.
func NewEnvAt(t *testing.T, listen string) *Env {
	t.Helper()

	dir := t.TempDir()
	env := &Env{Dir: dir, Config: filepath.Join(dir, "dnsgate.yaml"), CAFile: filepath.Join(dir, "tls.crt"), Listen: listen}

	GenerateKeys(t, env, "e2e")
	WriteTLSCert(t, env.CAFile, filepath.Join(dir, "tls.key"))
	WriteFile(t, filepath.Join(dir, "bootstrap-secret"), BootstrapSecret+"\n", 0o600)
	env.writeConfig(t, "")

	return env
}

// GenerateKeys writes a signing and an encryption key pair with the key ID
// suffix to env's keys directory.
func GenerateKeys(t *testing.T, env *Env, suffix string) {
	t.Helper()

	if _, err := keys.Generate(filepath.Join(env.Dir, "keys"), suffix); err != nil {
		t.Fatalf("generating keys: %v", err)
	}
}

// WriteDecryptionKeysConfig rewrites env's config file with entries as its
// keys.decryptionKeys list.
func (env *Env) WriteDecryptionKeysConfig(t *testing.T, entries string) {
	t.Helper()

	env.writeConfig(t, entries)
}

// writeConfig writes env's config file, with decryptionKeys, if any, as
// its keys.decryptionKeys list.
func (env *Env) writeConfig(t *testing.T, decryptionKeys string) {
	t.Helper()

	if decryptionKeys != "" {
		decryptionKeys = "  decryptionKeys:\n" + decryptionKeys
	}

	// Relative paths are resolved against the config file's directory.
	WriteFile(t, env.Config, `
listen: `+env.Listen+`
tls:
  certFile: tls.crt
  keyFile: tls.key
keys:
  signingKeyFile: keys/sig-e2e.pem
  encryptionKeyFile: keys/enc-e2e.pem
`+decryptionKeys+`bootstrapSecretFile: bootstrap-secret
database:
  sqliteFile: dnsgate.db
`, 0o600)
}

// WriteFile writes data to path with mode.
func WriteFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

// WriteTLSCert writes a self-signed certificate for 127.0.0.1 and its key.
func WriteTLSCert(t *testing.T, certFile, keyFile string) {
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

	WriteFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), 0o644)
	WriteFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), 0o600)
}

// Gateway is a Gateway running in the test process: the address it
// serves at, its audit stream and its logs.
type Gateway struct {
	Addr  string
	Audit *SyncBuffer
	Logs  *SyncBuffer
}

// RunFunc runs a Gateway that writes audit events to audit and logs to
// logs until ctx is done.
type RunFunc func(ctx context.Context, audit, logs io.Writer) error

// Start runs the Gateway configured by config, logging at info and
// calling providers, until the test ends, and waits for it to serve.
func Start(t *testing.T, config string, providers dnsprovider.Registry) *Gateway {
	t.Helper()

	return Launch(t, func(ctx context.Context, audit, logs io.Writer) error {
		return server.Run(ctx, server.Options{
			ConfigFile: config,
			LogLevel:   slog.LevelInfo,
			Audit:      audit,
			Log:        logs,
			Providers:  providers,
		})
	})
}

var listenAddr = regexp.MustCompile(`"address":"([^"]+)"`)

// Launch runs run until the test ends and waits for it to log its listen
// address.
func Launch(t *testing.T, run RunFunc) *Gateway {
	t.Helper()

	return launch(t, run, func(gw *Gateway) bool {
		m := listenAddr.FindStringSubmatch(gw.Logs.String())
		if m == nil {
			return false
		}

		gw.Addr = m[1]

		return true
	})
}

// LaunchAt runs run until the test ends and waits for it to accept
// connections at addr. It does not rely on the Gateway's logs.
func LaunchAt(t *testing.T, addr string, run RunFunc) *Gateway {
	t.Helper()

	return launch(t, run, func(gw *Gateway) bool {
		conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return false
		}

		_ = conn.Close()
		gw.Addr = addr

		return true
	})
}

// FreePort returns a local address no one listens on, for a Gateway whose
// logs do not tell its address.
func FreePort(t *testing.T) string {
	t.Helper()

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := lis.Addr().String()
	_ = lis.Close()

	return addr
}

// launch runs run until the test ends and waits until ready reports it is
// serving.
func launch(t *testing.T, run RunFunc, ready func(*Gateway) bool) *Gateway {
	t.Helper()

	gw := &Gateway{Audit: &SyncBuffer{}, Logs: &SyncBuffer{}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- run(ctx, gw.Audit, gw.Logs) }()

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
			t.Fatalf("server exited: %v\n%s", err, gw.Logs.String())
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Fatalf("server is not serving:\n%s", gw.Logs.String())

	return nil
}
