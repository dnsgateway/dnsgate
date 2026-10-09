package client_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
)

// scriptedGateway answers every Call by asking the client to open a
// relayed connection to host:port, recording the client's answer, then
// sending a Response.
type scriptedGateway struct {
	dnsgatev1.UnimplementedGatewayServiceServer

	host string
	port uint32

	mu     sync.Mutex
	opened *dnsgatev1.RelayOpened
}

func (g *scriptedGateway) Call(stream grpc.BidiStreamingServer[dnsgatev1.CallRequest, dnsgatev1.CallResponse]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}

	open := &dnsgatev1.RelayOpen{Id: 1, Host: g.host, Port: g.port}
	if err := stream.Send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Open{Open: open}}); err != nil {
		return err
	}

	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	g.mu.Lock()
	g.opened = msg.GetOpened()
	g.mu.Unlock()

	return stream.Send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Response{Response: &dnsgatev1.Response{
		Result: &dnsgatev1.Response_InspectToken{InspectToken: &dnsgatev1.InspectTokenResponse{}},
	}}})
}

// fakeNet resolves every host to addrs and records the addresses dialed.
type fakeNet struct {
	addrs []netip.Addr

	mu       sync.Mutex
	resolved []string
	dialed   []string
}

func (n *fakeNet) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	n.mu.Lock()
	n.resolved = append(n.resolved, host)
	n.mu.Unlock()

	if len(n.addrs) == 0 {
		return nil, errors.New("no such host")
	}

	return n.addrs, nil
}

func (n *fakeNet) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	n.mu.Unlock()

	conn, peer := net.Pipe()
	_ = peer.Close()

	return conn, nil
}

// openThrough has the Client, acting as Egress Agent through n, answer
// a RelayOpen for host:port, and returns its answer.
func openThrough(t *testing.T, n *fakeNet, host string, port uint32) *dnsgatev1.RelayOpened {
	t.Helper()

	gw := &scriptedGateway{host: host, port: port}

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	dnsgatev1.RegisterGatewayServiceServer(srv, gw)

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	c := client.New(conn, client.WithEgressAgent(client.EgressAgent{Resolver: n, Dialer: n}))
	if _, err := c.InspectToken(t.Context(), "token"); err != nil {
		t.Fatalf("InspectToken: %v", err)
	}

	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.opened == nil || gw.opened.GetId() != 1 {
		t.Fatalf("the client answered RelayOpen with %v, want a RelayOpened for it", gw.opened)
	}

	return gw.opened
}

func TestEgressAgentConnectsToPort443OfAPublicAddress(t *testing.T) {
	n := &fakeNet{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}

	opened := openThrough(t, n, "api.cloudflare.com", 443)
	if opened.GetError() != "" {
		t.Fatalf("RelayOpened error = %q, want none", opened.GetError())
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.resolved) != 1 || n.resolved[0] != "api.cloudflare.com" {
		t.Errorf("resolved %v, want api.cloudflare.com", n.resolved)
	}

	// The Egress Agent connects to the address it checked, not to the
	// name, which could resolve anew.
	if len(n.dialed) != 1 || n.dialed[0] != "203.0.113.7:443" {
		t.Errorf("dialed %v, want 203.0.113.7:443", n.dialed)
	}
}

func TestEgressAgentRefusesForbiddenDestinations(t *testing.T) {
	for name, tc := range map[string]struct {
		host  string
		port  uint32
		addrs []string
	}{
		"port 80":                 {"api.cloudflare.com", 80, []string{"203.0.113.7"}},
		"port 8443":               {"api.cloudflare.com", 8443, []string{"203.0.113.7"}},
		"port 0":                  {"api.cloudflare.com", 0, []string{"203.0.113.7"}},
		"loopback":                {"provider.example", 443, []string{"127.0.0.1"}},
		"loopback, not 127.0.0.1": {"provider.example", 443, []string{"127.8.9.10"}},
		"IPv6 loopback":           {"provider.example", 443, []string{"::1"}},
		"RFC1918 10/8":            {"provider.example", 443, []string{"10.1.2.3"}},
		"RFC1918 172.16/12":       {"provider.example", 443, []string{"172.16.0.1"}},
		"RFC1918 172.16/12 end":   {"provider.example", 443, []string{"172.31.255.254"}},
		"RFC1918 192.168/16":      {"provider.example", 443, []string{"192.168.1.1"}},
		"link-local":              {"provider.example", 443, []string{"169.254.10.20"}},
		"cloud metadata":          {"provider.example", 443, []string{"169.254.169.254"}},
		"IPv6 link-local":         {"provider.example", 443, []string{"fe80::1"}},
		"CGNAT":                   {"provider.example", 443, []string{"100.64.0.1"}},
		"CGNAT end":               {"provider.example", 443, []string{"100.127.255.254"}},
		"IPv6 ULA fc00::/7":       {"provider.example", 443, []string{"fc00::1"}},
		"IPv6 ULA fd00::/8":       {"provider.example", 443, []string{"fd12:3456::1"}},
		"unspecified":             {"provider.example", 443, []string{"0.0.0.0"}},
		"IPv6 unspecified":        {"provider.example", 443, []string{"::"}},
		"IPv4-mapped loopback":    {"provider.example", 443, []string{"::ffff:127.0.0.1"}},
		"IPv4-mapped metadata":    {"provider.example", 443, []string{"::ffff:169.254.169.254"}},
		// One forbidden address refuses the host, whatever else it
		// resolves to.
		"public and private": {"provider.example", 443, []string{"203.0.113.7", "10.0.0.1"}},
		"loopback literal":   {"127.0.0.1", 443, nil},
		"metadata literal":   {"169.254.169.254", 443, nil},
		"IPv6 literal":       {"::1", 443, nil},
		"unresolvable":       {"nowhere.example", 443, nil},
	} {
		t.Run(name, func(t *testing.T) {
			n := &fakeNet{}
			for _, a := range tc.addrs {
				n.addrs = append(n.addrs, netip.MustParseAddr(a))
			}

			opened := openThrough(t, n, tc.host, tc.port)
			if opened.GetError() == "" {
				t.Error("the Egress Agent connected, want it to refuse")
			}

			n.mu.Lock()
			defer n.mu.Unlock()

			if len(n.dialed) != 0 {
				t.Errorf("dialed %v, want nothing", n.dialed)
			}
		})
	}
}
