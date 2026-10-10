package gatewayadapter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

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

	mu sync.Mutex
	// requests are the Requests the Gateway received, in order.
	requests []*dnsgatev1.Request
	// beforeWrite, if set, runs as the Gateway receives a record write,
	// before it carries it out.
	beforeWrite func()
	// extras are Record Extras the fake's Provider type declares beyond
	// its proxy flag.
	extras []dnsprovider.ExtraSpec
}

// recordRequests is a stream interceptor that keeps each Request the
// Gateway receives.
func (h *harness) recordRequests(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &recordingStream{ServerStream: ss, h: h})
}

type recordingStream struct {
	grpc.ServerStream

	h *harness
}

func (s *recordingStream) RecvMsg(m any) error {
	if err := s.ServerStream.RecvMsg(m); err != nil {
		return err
	}

	if req := m.(*dnsgatev1.CallRequest).GetRequest(); req != nil {
		s.h.mu.Lock()
		s.h.requests = append(s.h.requests, proto.CloneOf(req))
		hook := s.h.beforeWrite
		s.h.mu.Unlock()

		switch req.GetOperation().(type) {
		case *dnsgatev1.Request_CreateRecord, *dnsgatev1.Request_UpdateRecord, *dnsgatev1.Request_DeleteRecord, *dnsgatev1.Request_PatchRecord:
			if hook != nil {
				hook()
			}
		}
	}

	return nil
}

// writes returns the record writes the Gateway received, one line each:
// the operation, the RRset's name and type, and for create and update
// its TTL and values, each with its Record Extras, and for update and
// delete the Expected RRset, as "expect TTL VALUES".
func (h *harness) writes() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	var out []string

	for _, req := range h.requests {
		switch op := req.GetOperation().(type) {
		case *dnsgatev1.Request_CreateRecord:
			r := op.CreateRecord
			out = append(out, fmt.Sprintf("create %s %s %d %s", r.GetName(), r.GetType(), r.GetTtl(), formatValues(r.GetRecords())))
		case *dnsgatev1.Request_UpdateRecord:
			r := op.UpdateRecord
			out = append(out, fmt.Sprintf("update %s %s %d %s expect %s", r.GetName(), r.GetType(), r.GetTtl(), formatValues(r.GetRecords()), formatExpect(r.GetExpect())))
		case *dnsgatev1.Request_DeleteRecord:
			r := op.DeleteRecord
			out = append(out, fmt.Sprintf("delete %s %s expect %s", r.GetName(), r.GetType(), formatExpect(r.GetExpect())))
		case *dnsgatev1.Request_PatchRecord:
			out = append(out, "patch "+op.PatchRecord.GetName())
		}
	}

	return out
}

func formatExpect(e *dnsgatev1.ExpectedRRset) string {
	if e == nil {
		return "none"
	}

	return fmt.Sprintf("%d %s", e.GetTtl(), formatValues(e.GetRecords()))
}

// formatValues formats values as "[v1{k=v} v2]", Record Extras sorted by
// key.
func formatValues(values []*dnsgatev1.RecordValue) string {
	parts := make([]string, 0, len(values))

	for _, v := range values {
		var extras []string
		for _, k := range slices.Sorted(maps.Keys(v.GetExtras())) {
			extras = append(extras, k+"="+v.GetExtras()[k])
		}

		part := v.GetValue()
		if len(extras) > 0 {
			part += "{" + strings.Join(extras, ",") + "}"
		}

		parts = append(parts, part)
	}

	return "[" + strings.Join(parts, " ") + "]"
}

// wantWrites checks that the Gateway received exactly the record writes
// want since the last call, as writes formats them.
func wantWrites(t *testing.T, h *harness, want ...string) {
	t.Helper()

	got := h.writes()

	h.mu.Lock()
	h.requests = nil
	h.mu.Unlock()

	if !slices.Equal(got, want) {
		t.Errorf("writes =\n\t%s\nwant\n\t%s", strings.Join(got, "\n\t"), strings.Join(want, "\n\t"))
	}
}

// newHarness serves a Gateway whose fake Provider holds example.com,
// takes each Changeset whole, as a Batcher, proxies A, AAAA and CNAME
// Records and reads TTL 1 as automatic, as Cloudflare does. Its Provider
// type declares extras too.
func newHarness(t *testing.T, extras ...dnsprovider.ExtraSpec) *harness {
	t.Helper()

	h := &harness{fake: providertest.New(), extras: extras}
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

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	h.addr = lis.Addr().String()

	srv := grpc.NewServer(grpc.StreamInterceptor(h.recordRequests), grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})))
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

// registry is the Gateway's Providers: the fake, as "cloudflare", with
// the harness's extras.
func (h *harness) registry() dnsprovider.Registry {
	f := h.fake.Factory()
	f.Extras = append(f.Extras, h.extras...)

	return dnsprovider.Registry{"cloudflare": f}
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
