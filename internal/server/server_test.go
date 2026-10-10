package server_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// dial connects to gw over TLS, trusting env's CA.
func dial(t *testing.T, env *servertest.Env, gw *servertest.Gateway) *client.Client {
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

	t.Cleanup(func() { _ = conn.Close() })

	return client.New(conn)
}

func TestRunServesTheGatewayWithTheGivenProviders(t *testing.T) {
	fake := providertest.New().AddZone(dnsprovider.Zone{ID: "z-com", Name: "example.com", State: dnsprovider.HostingActive})

	env := servertest.NewEnv(t)
	gw := servertest.Start(t, env.Config, dnsprovider.Registry{"cloudflare": fake.Factory()})
	c := dial(t, env, gw)

	onboarded, err := c.Onboard(t.Context(), &dnsgatev1.OnboardRequest{
		BootstrapSecret: servertest.BootstrapSecret,
		Provider:        "cloudflare",
		Credential:      &dnsgatev1.Credential{Type: "api-token", Value: "cf-api-token"},
	})
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	zones, err := c.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: onboarded.GetToken()})
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}

	if got := zones.GetZones(); len(got) != 1 || got[0].GetName() != "example.com" {
		t.Errorf("ListZones = %v, want the fake Provider's example.com", got)
	}

	if audit := gw.Audit.String(); !strings.Contains(audit, `"event":"onboard"`) {
		t.Errorf("audit stream has no onboard event:\n%s", audit)
	}
}
