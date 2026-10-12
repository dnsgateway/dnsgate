package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"os"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// serverCmd runs "dnsgate server --config --listen" with the TLS
// certificate next to config and args.
func serverCmd(config, listen string, args []string) servertest.RunFunc {
	cmd := newRootCmd()
	cmd.SetArgs(append(append([]string{"server", "--config", config, "--listen", listen}, tlsArgs(config)...), args...))

	return func(ctx context.Context, audit, logs io.Writer) error {
		cmd.SetOut(audit)
		cmd.SetErr(logs)

		return cmd.ExecuteContext(ctx)
	}
}

// tlsArgs returns the TLS flags of the certificate next to config.
func tlsArgs(config string) []string {
	certFile, keyFile := servertest.TLSFiles(config)

	return []string{"--tls-cert-file", certFile, "--tls-key-file", keyFile}
}

// startServer runs "dnsgate server --config" on an ephemeral port with args
// until the test ends and waits for it to log its listen address.
func startServer(t *testing.T, config string, args ...string) *servertest.Gateway {
	t.Helper()

	return servertest.Launch(t, serverCmd(config, "127.0.0.1:0", args))
}

// startServerAt runs "dnsgate server --config" for env with args until the
// test ends and waits for it to accept connections at env's listen address.
// It does not rely on the server's logs.
func startServerAt(t *testing.T, env *servertest.Env, args ...string) *servertest.Gateway {
	t.Helper()

	return servertest.LaunchAt(t, env.Listen, serverCmd(env.Config, env.Listen, args))
}

// onboard onboards a Cloudflare credential at gw, trusting env's CA.
func onboard(t *testing.T, env *servertest.Env, gw *servertest.Gateway) error {
	t.Helper()

	pem, err := os.ReadFile(env.CAFile)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)

	conn, err := grpc.NewClient(gw.Addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = conn.Close() }()

	_, err = client.New(conn).Onboard(t.Context(), &dnsgatev1.OnboardRequest{
		BootstrapSecret: servertest.BootstrapSecret,
		Provider:        "cloudflare",
		Credential:      &dnsgatev1.Credential{Type: "api-token", Value: "cf-api-token-E2E-SECRET"},
	})

	return err
}
