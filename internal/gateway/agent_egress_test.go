package gateway_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// agentIP is the public address the Egress Agent's resolver gives
// api.cloudflare.com.
var agentIP = netip.MustParseAddr("203.0.113.7")

// agentNet is the network of the client acting as Egress Agent: it
// resolves api.cloudflare.com to agentIP, connects every address to the
// fake Cloudflare's TLS server, and taps the bytes it relays.
type agentNet struct {
	target string

	mu     sync.Mutex
	dialed []string
	// sent and received are the bytes the Egress Agent relayed to and from
	// the Provider.
	sent, received bytes.Buffer
}

func (n *agentNet) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != cloudflareHost {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return []netip.Addr{agentIP}, nil
}

func (n *agentNet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	n.mu.Unlock()

	var d net.Dialer

	conn, err := d.DialContext(ctx, network, n.target)
	if err != nil {
		return nil, err
	}

	tcp, _ := conn.(*net.TCPConn)

	return &tapConn{TCPConn: tcp, net: n}, nil
}

func (n *agentNet) dials() []string {
	n.mu.Lock()
	defer n.mu.Unlock()

	return slices.Clone(n.dialed)
}

// tapConn copies what passes through a TCP connection into its agentNet.
type tapConn struct {
	*net.TCPConn

	net *agentNet
}

func (c *tapConn) Read(p []byte) (int, error) {
	n, err := c.TCPConn.Read(p)

	c.net.mu.Lock()
	c.net.received.Write(p[:n])
	c.net.mu.Unlock()

	return n, err
}

func (c *tapConn) Write(p []byte) (int, error) {
	c.net.mu.Lock()
	c.net.sent.Write(p)
	c.net.mu.Unlock()

	return c.TCPConn.Write(p)
}

// testCA is a certificate authority for test servers.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dnsgate test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{cert: cert, key: key, pool: pool}
}

// issue returns a server certificate for host signed by ca.
func (ca *testCA) issue(t *testing.T, host string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// agentHarness is a Gateway running the real Cloudflare Provider against
// a fake Cloudflare API served over TLS as api.cloudflare.com, with a
// client that acts as Egress Agent.
type agentHarness struct {
	*harness

	cf  *fakeCloudflare
	net *agentNet
	srv *httptest.Server
	// openConns counts the connections to the fake Cloudflare that are
	// open.
	openConns atomic.Int32
}

// providerCert is the certificate the fake Cloudflare presents.
type providerCert int

const (
	// trustedCert is for api.cloudflare.com, issued by the CA the Gateway
	// trusts.
	trustedCert providerCert = iota
	// untrustedCert is for api.cloudflare.com, issued by another CA.
	untrustedCert
	// wrongHostCert is issued by the CA the Gateway trusts, for another
	// host.
	wrongHostCert
)

// newAgentHarness returns an agentHarness whose fake Cloudflare presents
// cert.
func newAgentHarness(t *testing.T, cert providerCert) *agentHarness {
	t.Helper()

	cf := newFakeCloudflare()

	trusted := newTestCA(t)

	issuer, host := trusted, cloudflareHost

	switch cert {
	case trustedCert:
	case untrustedCert:
		issuer = newTestCA(t)
	case wrongHostCert:
		host = "api.example.net"
	}

	srv := httptest.NewUnstartedServer(cf.handler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{issuer.issue(t, host)}, MinVersion: tls.VersionTLS12}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // failed handshakes are expected

	ah := &agentHarness{cf: cf, srv: srv}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s { //nolint:exhaustive // the others leave the count as it is
		case http.StateNew:
			ah.openConns.Add(1)
		case http.StateClosed, http.StateHijacked:
			ah.openConns.Add(-1)
		}
	}

	srv.StartTLS()
	t.Cleanup(srv.Close)

	an := &agentNet{target: srv.Listener.Addr().String()}

	h := newHarness(t)
	h.providers = provider.Registry()
	h.egress = cf.gatewayTransport(srv, trusted.pool)
	h.agentRoots = trusted.pool
	h.agent = &client.EgressAgent{Resolver: an, Dialer: an}
	h.serve(t, h.keys)

	ah.harness, ah.net = h, an

	return ah
}

// gatewayTransport is a Gateway Egress Transport that dials srv for
// every address, records the address in cf.dialed, and trusts roots
// alone.
func (cf *fakeCloudflare) gatewayTransport(srv *httptest.Server, roots *x509.CertPool) http.RoundTripper {
	dialer := &net.Dialer{}

	return &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			cf.mu.Lock()
			cf.dialed = append(cf.dialed, addr)
			cf.mu.Unlock()

			return dialer.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
}

func TestAgentEgressReadsAndChangesCloudflareRecords(t *testing.T) {
	h := newAgentHarness(t, trustedCert)

	root := h.onboard(t, onboardRequest())
	agent := dnsgatev1.Egress_EGRESS_AGENT

	record, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{
		Token: root, Egress: agent, Zone: "example.com", Name: "www.apps", Type: "A",
	})
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if got, want := recordSets([]*dnsgatev1.RecordSet{record.GetRecordSet()})[0], "www.apps A 120 192.0.2.10,192.0.2.11"; got != want {
		t.Errorf("RRset = %q, want %q", got, want)
	}

	if _, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Egress: agent, Zone: "example.com", Name: "api", Type: "AAAA", Ttl: 120, Values: []string{"2001:db8::1"},
	}); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	records, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: root, Egress: agent, Zone: "example.com"})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	if got := recordSets(records.GetRecordSets()); !slices.Contains(got, "api AAAA 120 2001:db8::1") {
		t.Errorf("RRsets = %v, want the created api AAAA", got)
	}

	// Every connection to Cloudflare left from the client, to the address
	// it resolved, and none from the Gateway.
	dials := h.net.dials()
	if len(dials) == 0 {
		t.Fatal("the Egress Agent opened no connection")
	}

	for _, addr := range dials {
		if addr != netip.AddrPortFrom(agentIP, 443).String() {
			t.Errorf("Egress Agent dialed %s, want %s:443", addr, agentIP)
		}
	}

	h.cf.mu.Lock()
	gatewayDials, seen := slices.Clone(h.cf.dialed), slices.Clone(h.cf.seen)
	h.cf.mu.Unlock()

	if len(gatewayDials) != 0 {
		t.Errorf("Gateway Egress dialed %v, want nothing", gatewayDials)
	}

	for _, r := range seen {
		if r.host != cloudflareHost || r.authorization != "Bearer "+cfToken {
			t.Errorf("request to %s with Authorization %q, want %s with the Provider Credential", r.host, r.authorization, cloudflareHost)
		}
	}

	// The client relayed TLS records alone: never the Provider Credential
	// or plaintext HTTP.
	h.net.mu.Lock()
	sent, received := slices.Clone(h.net.sent.Bytes()), slices.Clone(h.net.received.Bytes())
	h.net.mu.Unlock()

	for dir, b := range map[string][]byte{"to the Provider": sent, "from the Provider": received} {
		if len(b) < 3 || b[0] != 0x16 || b[1] != 0x03 {
			t.Errorf("bytes relayed %s start % x, want a TLS handshake record", dir, b[:min(len(b), 3)])
		}

		for _, plain := range []string{cfToken, "Bearer", "HTTP/1.1", "dns_records", "example.com", "192.0.2.10"} {
			if bytes.Contains(b, []byte(plain)) {
				t.Errorf("bytes relayed %s contain %q in plaintext", dir, plain)
			}
		}
	}

	// The mutation's audit event names the Egress asked for and used.
	var create map[string]any

	for _, e := range h.auditEvents(t) {
		if e["event"] == "records.create" {
			create = e
		}
	}

	if create["result"] != "ok" || create["requested_egress"] != "agent" || create["egress"] != "agent" {
		t.Errorf("audit event = %v, want an ok records.create, agent egress asked for and used", create)
	}

	if strings.Contains(h.audit.String(), cfToken) {
		t.Errorf("audit log contains the Provider Credential:\n%s", h.audit.String())
	}
}

func TestAgentEgressFailsOnABadProviderCertificate(t *testing.T) {
	for name, cert := range map[string]providerCert{
		"untrusted CA": untrustedCert,
		"wrong host":   wrongHostCert,
	} {
		t.Run(name, func(t *testing.T) {
			h := newAgentHarness(t, cert)

			root := h.onboard(t, onboardRequest())

			_, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{
				Token: root, Egress: dnsgatev1.Egress_EGRESS_AGENT, Zone: "example.com",
			})
			wantError(t, err, codes.Unavailable, dnsgatev1.Error_CATEGORY_INTERNAL)

			if len(h.net.dials()) == 0 {
				t.Error("the Egress Agent opened no connection")
			}

			// The handshake failed before any request, so the Provider Credential
			// never left the Gateway.
			h.cf.mu.Lock()
			defer h.cf.mu.Unlock()

			if len(h.cf.seen) != 0 {
				t.Errorf("Cloudflare got %d requests, want none", len(h.cf.seen))
			}

			if e := h.auditEvents(t); e[len(e)-1]["result"] != "failed" || e[len(e)-1]["egress"] != "agent" {
				t.Errorf("audit event = %v, want a failed request through agent egress", e[len(e)-1])
			}
		})
	}
}

func TestAgentEgressFailsWhenTheEgressAgentRefuses(t *testing.T) {
	h := newAgentHarness(t, trustedCert)

	// The client resolves the Provider to its own network.
	h.agent.Resolver = staticResolver{netip.MustParseAddr("10.0.0.53")}
	h.serve(t, h.keys)

	root := h.onboard(t, onboardRequest())

	_, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{
		Token: root, Egress: dnsgatev1.Egress_EGRESS_AGENT, Zone: "example.com", Name: "www.apps", Type: "A",
	})
	wantError(t, err, codes.Unavailable, dnsgatev1.Error_CATEGORY_INTERNAL)

	if !strings.Contains(err.Error(), "egress agent") {
		t.Errorf("error = %v, want it to name the egress agent", err)
	}

	if dials := h.net.dials(); len(dials) != 0 {
		t.Errorf("the Egress Agent dialed %v, want nothing", dials)
	}
}

// settle waits until the fake Cloudflare has no open connection and the
// process runs no more goroutines than baseline, and fails the test with
// the goroutines still running if that takes too long.
func (h *agentHarness) settle(t *testing.T, baseline int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for h.openConns.Load() != 0 || runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("%d connections to Cloudflare open, %d goroutines running, want none and at most %d:\n%s",
				h.openConns.Load(), runtime.NumGoroutine(), baseline, buf[:n])
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestAgentEgressRelayEndsWithTheRequest(t *testing.T) {
	h := newAgentHarness(t, trustedCert)

	root := h.onboard(t, onboardRequest())
	baseline := runtime.NumGoroutine()

	for range 3 {
		if _, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{
			Token: root, Egress: dnsgatev1.Egress_EGRESS_AGENT, Zone: "example.com",
		}); err != nil {
			t.Fatalf("ListRecords: %v", err)
		}
	}

	h.settle(t, baseline)
}

func TestAgentEgressRelayEndsWhenTheClientCancels(t *testing.T) {
	h := newAgentHarness(t, trustedCert)

	root := h.onboard(t, onboardRequest())
	baseline := runtime.NumGoroutine()

	// Cloudflare holds every request until its connection closes.
	entered := make(chan struct{}, 1)
	h.cf.fail = func(_ http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}

		<-r.Context().Done()
	}

	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)

	go func() {
		_, err := h.client.ListRecords(ctx, &dnsgatev1.ListRecordsRequest{
			Token: root, Egress: dnsgatev1.Egress_EGRESS_AGENT, Zone: "example.com",
		})
		errc <- err
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached Cloudflare")
	}

	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the canceled request succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the canceled request did not return")
	}

	// The relayed connection closes, and the Gateway's and the client's
	// goroutines for the stream end.
	h.settle(t, baseline)
}

// staticResolver resolves every host to its addresses.
type staticResolver []netip.Addr

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r, nil
}

func TestEgressSelection(t *testing.T) {
	read := []string{"get", "list"}

	for name, tc := range map[string]struct {
		egress    []string
		requested dnsgatev1.Egress
		// used is the Egress the request goes through, empty if it is
		// refused with code and category.
		used     string
		code     codes.Code
		category dnsgatev1.Error_Category
	}{
		"none asked, both allowed":    {nil, dnsgatev1.Egress_EGRESS_UNSPECIFIED, "gateway", codes.OK, 0},
		"gateway asked and allowed":   {[]string{"gateway"}, dnsgatev1.Egress_EGRESS_GATEWAY, "gateway", codes.OK, 0},
		"gateway asked, both allowed": {nil, dnsgatev1.Egress_EGRESS_GATEWAY, "gateway", codes.OK, 0},
		"agent asked, both allowed":   {nil, dnsgatev1.Egress_EGRESS_AGENT, "agent", codes.OK, 0},
		"agent asked and allowed":     {[]string{"agent"}, dnsgatev1.Egress_EGRESS_AGENT, "agent", codes.OK, 0},
		// A token limited to Agent Egress never falls back to Gateway
		// Egress.
		"none asked, agent only": {[]string{"agent"}, dnsgatev1.Egress_EGRESS_UNSPECIFIED, "agent", codes.OK, 0},
		"agent asked, gateway only": {
			[]string{"gateway"}, dnsgatev1.Egress_EGRESS_AGENT, "", codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"gateway asked, agent only": {
			[]string{"agent"}, dnsgatev1.Egress_EGRESS_GATEWAY, "", codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"unknown egress": {
			nil, dnsgatev1.Egress(42), "", codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newAgentHarness(t, trustedCert)

			tok := h.mint(t, nil, token.Permission{Verbs: read, Egress: tc.egress})

			_, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: tok, Zone: "example.com", Egress: tc.requested})

			h.cf.mu.Lock()
			gatewayDials, seen := len(h.cf.dialed), len(h.cf.seen)
			h.cf.mu.Unlock()

			agentDials := len(h.net.dials())

			switch tc.used {
			case "gateway":
				if err != nil {
					t.Fatalf("ListRecords: %v", err)
				}

				if gatewayDials == 0 || agentDials != 0 {
					t.Errorf("Gateway Egress dialed %d times, the Egress Agent %d, want Gateway Egress alone", gatewayDials, agentDials)
				}
			case "agent":
				if err != nil {
					t.Fatalf("ListRecords: %v", err)
				}

				if gatewayDials != 0 || agentDials == 0 {
					t.Errorf("Gateway Egress dialed %d times, the Egress Agent %d, want the Egress Agent alone", gatewayDials, agentDials)
				}
			default:
				wantError(t, err, tc.code, tc.category)

				if gatewayDials+agentDials+seen != 0 {
					t.Errorf("the refused request reached Cloudflare: %d Gateway dials, %d Egress Agent dials, %d requests", gatewayDials, agentDials, seen)
				}

				if e := h.auditEvents(t); len(e) != 1 || e[0]["result"] != "denied" {
					t.Errorf("audit events = %v, want one denial", e)
				}
			}
		})
	}
}
