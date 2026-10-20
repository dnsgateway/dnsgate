package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/dnsgateway/dnsgate-go/client"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// runCLI runs dnsgate-acme with args and returns its output.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)

	err := cmd.ExecuteContext(t.Context())

	return out.String(), err
}

// mapArgs returns the flag that gives dnsgate-acme the Challenge Map
// testMap.
func mapArgs(t *testing.T) []string {
	t.Helper()

	return []string{"--challenge-map", writeMap(t, "map.yaml", testMap)}
}

// daemonCmd returns a run of dnsgate-acme with the Challenge Map testMap,
// then args, that writes its logs to the given writer. Its Gateway client
// takes opts.
func daemonCmd(t *testing.T, args []string, opts ...client.Option) servertest.RunFunc {
	t.Helper()

	return commandRun(append(mapArgs(t), args...), opts...)
}

// commandRun returns a run of dnsgate-acme with exactly args that writes
// its logs to the given writer. Its Gateway client takes opts.
func commandRun(args []string, opts ...client.Option) servertest.RunFunc {
	cmd := newRootCmd(opts...)
	cmd.SetArgs(args)

	return func(ctx context.Context, _, logs io.Writer) error {
		cmd.SetOut(io.Discard)
		cmd.SetErr(logs)

		return cmd.ExecuteContext(ctx)
	}
}

// startDaemon runs dnsgate-acme with args on an ephemeral port until the
// test ends and waits for it to log its listen address.
func startDaemon(t *testing.T, args ...string) *servertest.Gateway {
	t.Helper()

	return startDaemonWith(t, nil, args...)
}

// startDaemonWith is startDaemon with a Gateway client that takes opts.
func startDaemonWith(t *testing.T, opts []client.Option, args ...string) *servertest.Gateway {
	t.Helper()

	return servertest.Launch(t, daemonCmd(t, append([]string{"--listen", "127.0.0.1:0"}, args...), opts...))
}

// get sends a request with method to url through c and returns the status
// and body.
func send(t *testing.T, c *http.Client, method, url string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, url, nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, string(body)
}

// checkEndpoints checks the endpoints that need no Gateway at base.
func checkEndpoints(t *testing.T, c *http.Client, base string) {
	t.Helper()

	if code, body := send(t, c, http.MethodGet, base+"/health"); code != http.StatusOK || body != "" {
		t.Errorf("GET /health = %d %q, want 200 with an empty body", code, body)
	}

	if code, _ := send(t, c, http.MethodPost, base+"/register"); code != http.StatusNotFound {
		t.Errorf("POST /register = %d, want 404", code)
	}
}

func TestDaemonServesPlainHTTPWithoutTLSFiles(t *testing.T) {
	d := startDaemon(t)

	checkEndpoints(t, &http.Client{}, "http://"+d.Addr)
}

// httpsClient returns a client that trusts the certificate in certFile and
// speaks at most TLS version maxVersion.
func httpsClient(t *testing.T, certFile string, maxVersion uint16) *http.Client {
	t.Helper()

	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)

	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, MaxVersion: maxVersion},
	}}
}

// writeTLSFiles writes a certificate for 127.0.0.1 and its key, and
// returns their paths.
func writeTLSFiles(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	servertest.WriteTLSCert(t, cert, key)

	return cert, key
}

func TestDaemonServesHTTPSWithTLSFiles(t *testing.T) {
	cert, key := writeTLSFiles(t)
	d := startDaemon(t, "--tls-cert-file", cert, "--tls-key-file", key)

	// TLS 1.2 still works, for ACME clients and Proxmox on older stacks.
	for name, maxVersion := range map[string]uint16{"TLS 1.3": tls.VersionTLS13, "TLS 1.2": tls.VersionTLS12} {
		t.Run(name, func(t *testing.T) {
			checkEndpoints(t, httpsClient(t, cert, maxVersion), "https://"+d.Addr)
		})
	}

	if code, _ := send(t, &http.Client{}, http.MethodGet, "http://"+d.Addr+"/health"); code == http.StatusOK {
		t.Error("GET /health over plain HTTP to the HTTPS daemon = 200, want a refusal")
	}
}
