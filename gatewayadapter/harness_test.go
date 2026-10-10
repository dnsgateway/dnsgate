package gatewayadapter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/gatewayadapter"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/client"
	"github.com/dnsgateway/dnsgate/internal/gateway"
	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/revocation"
	"github.com/dnsgateway/dnsgate/internal/token"
)

const bootstrapSecret = "bootstrap-secret-0123456789"

// harness is a Gateway served in-process over TLS on a loopback port, with
// a fake Provider behind it as "cloudflare", and a Root Token for it.
type harness struct {
	// addr is the Gateway's address, host:port.
	addr string
	// roots trust the Gateway's certificate.
	roots *x509.CertPool
	// fake is the Provider the Gateway calls.
	fake *providertest.Provider
	// client calls the Gateway directly, to set tokens up.
	client *client.Client
	// root is the Root Token.
	root string
}

// newHarness serves a Gateway whose fake Provider holds example.com,
// takes each Changeset whole, as a Batcher, proxies A, AAAA and CNAME
// Records and reads TTL 1 as automatic, as Cloudflare does.
func newHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{fake: providertest.New()}
	h.fake.AddZone(dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingActive, Nameservers: []string{"ns1.example.net"}})
	h.fake.SetBatcher(true)
	h.fake.SetProxiableTypes("A", "AAAA", "CNAME")
	h.fake.SetAutoTTL(true)

	keyDir := filepath.Join(t.TempDir(), "keys")
	if _, err := keys.Generate(keyDir, "test"); err != nil {
		t.Fatal(err)
	}

	src, err := keys.LoadFiles(filepath.Join(keyDir, "sig-test.pem"), filepath.Join(keyDir, "enc-test.pem"))
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := revocation.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "dnsgate.db"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = revoked.Close() })

	gw := gateway.New(gateway.Config{
		Keys:            src,
		BootstrapSecret: token.NewSecret(bootstrapSecret),
		Audit:           audit.New(io.Discard),
		Providers:       h.registry(),
		RevokedIDs:      revoked,
	})

	cert, roots := selfSigned(t)
	h.roots = roots

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	h.addr = lis.Addr().String()

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})))
	dnsgatev1.RegisterGatewayServiceServer(srv, gw)

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	h.client = client.New(conn)

	resp, err := h.client.Onboard(t.Context(), &dnsgatev1.OnboardRequest{
		BootstrapSecret: bootstrapSecret,
		Provider:        "cloudflare",
		Credential:      &dnsgatev1.Credential{Type: "api-token", Value: "cf-api-token"},
	})
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	h.root = resp.GetToken()

	return h
}

// registry is the Gateway's Providers: the fake, as "cloudflare".
func (h *harness) registry() dnsprovider.Registry {
	return dnsprovider.Registry{"cloudflare": h.fake.Factory()}
}

// derive issues a Derived Token of the Root Token with perms.
func (h *harness) derive(t *testing.T, perms ...*dnsgatev1.Permission) string {
	t.Helper()

	resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{Token: h.root, Sub: "dnscli", Permissions: perms})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	return resp.GetToken()
}

// factory is the Gateway Adapter's Factory, trusting the harness's
// Gateway, and reading Provider types from the Gateway's own Providers.
func (h *harness) factory() dnsprovider.Factory {
	return gatewayadapter.Factory(gatewayadapter.WithRootCAs(h.roots), gatewayadapter.WithProviders(h.registry()))
}

// provider builds a Gateway Adapter for tok through the Factory.
func (h *harness) provider(t *testing.T, tok string) dnsprovider.Provider {
	t.Helper()

	p, err := h.factory().New(map[string]string{gatewayadapter.FieldGateway: h.addr, gatewayadapter.FieldToken: tok})
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// zone reads example.com through p.
func zone(t *testing.T, p dnsprovider.Provider) dnsprovider.Zone {
	t.Helper()

	z, err := p.Zone(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}

	return z
}

// selfSigned returns a certificate for 127.0.0.1 and a pool trusting it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gateway"},
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

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}
