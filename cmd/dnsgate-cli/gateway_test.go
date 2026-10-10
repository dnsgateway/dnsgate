package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/dnsgateway/dnsprovider"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

const (
	testBootstrapSecret = servertest.BootstrapSecret
	testCFToken         = "cf-api-token-E2E-SECRET"
)

// startServer runs the Gateway configured by config, calling providers,
// in the test process until the test ends and waits for it to serve.
func startServer(t *testing.T, config string, providers dnsprovider.Registry) *servertest.Gateway {
	t.Helper()

	return servertest.Start(t, config, providers)
}

// runCLI runs dnsgate-cli with args, returning stdout and stderr together.
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

// runClient runs a dnsgate-cli command against gw, trusting env's CA,
// returning stdout and the error; stderr is discarded.
func runClient(t *testing.T, env *servertest.Env, gw *servertest.Gateway, args ...string) (string, error) {
	t.Helper()

	out, _, err := runClientStderr(t, env, gw, args...)

	return out, err
}

// runClientStderr is runClient returning stderr too.
func runClientStderr(t *testing.T, env *servertest.Env, gw *servertest.Gateway, args ...string) (string, string, error) {
	t.Helper()

	var out, errOut bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(append(args, "--gateway", gw.Addr, "--ca-file", env.CAFile))

	err := cmd.ExecuteContext(t.Context())

	return out.String(), errOut.String(), err
}

// writeUnrelatedCAFile writes a self-signed certificate that does not sign
// the Gateway's certificate and returns its path.
func writeUnrelatedCAFile(t *testing.T) string {
	t.Helper()

	certFile := filepath.Join(t.TempDir(), "other.crt")
	servertest.WriteTLSCert(t, certFile, filepath.Join(t.TempDir(), "other.key"))

	return certFile
}
