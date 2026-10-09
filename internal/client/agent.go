package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/grpc"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// The relay framing is recorded in ADR 0006.
const (
	// dialTimeout bounds the default Dialer's connection to a Provider.
	dialTimeout = 10 * time.Second
	// writeTimeout bounds each write of the Gateway's bytes to a
	// Provider: a Provider that stops reading must not hold the stream.
	writeTimeout = 30 * time.Second
)

// Resolver resolves a hostname to its addresses, as a *net.Resolver does.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens network connections, as a *net.Dialer does.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// EgressAgent is how a Client acts as Egress Agent: how it resolves and
// connects to the Provider host the Gateway names for Agent Egress. The
// Client relays the connection's bytes, the Gateway's TLS session with
// the Provider, and never reads them.
type EgressAgent struct {
	// Resolver resolves the Provider's hostname; nil means
	// net.DefaultResolver.
	Resolver Resolver
	// Dialer connects to the Provider's address; nil means a net.Dialer
	// that gives up after 10 seconds.
	Dialer Dialer
}

// Option configures a Client.
type Option func(*Client)

// WithEgressAgent makes the Client act as Egress Agent through a.
func WithEgressAgent(a EgressAgent) Option {
	return func(c *Client) { c.agent = a }
}

// providerPort is the only port the Egress Agent connects to (ADR 0002).
const providerPort = 443

// forbiddenPrefixes are the addresses the Egress Agent never connects to
// (ADR 0002): a Provider's API is on none of them, and reaching them from
// the client's network would let the Gateway into it.
var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // unspecified, "this network"
	netip.MustParsePrefix("127.0.0.0/8"),    // loopback
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918
	netip.MustParsePrefix("169.254.0.0/16"), // link-local, cloud metadata 169.254.169.254
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("::1/128"),        // loopback
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("fc00::/7"),       // unique local
}

// forbidden reports whether addr is one the Egress Agent never connects to.
func forbidden(addr netip.Addr) bool {
	addr = addr.Unmap()

	for _, p := range forbiddenPrefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// connect connects to the destination the Gateway names in o, if the
// destination rules allow it: the port must be 443, and the host must
// resolve to no forbidden address. It connects to the first address that
// answers, by the address it checked rather than by name.
func (a EgressAgent) connect(ctx context.Context, o *dnsgatev1.RelayOpen) (net.Conn, error) {
	host, port := o.GetHost(), o.GetPort()
	if port != providerPort {
		return nil, fmt.Errorf("port %d refused: the egress agent connects to port %d alone", port, providerPort)
	}

	resolver := a.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	dialer := a.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: dialTimeout}
	}

	var addrs []netip.Addr

	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	} else if addrs, err = resolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, errors.New("resolving the provider host failed")
	}

	for _, addr := range addrs {
		if forbidden(addr) {
			return nil, fmt.Errorf("address %s refused: the egress agent connects to public addresses alone", addr)
		}
	}

	var dialErr error

	for _, addr := range addrs {
		conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr.Unmap(), providerPort).String())
		if err == nil {
			return conn, nil
		}

		dialErr = err
	}

	if dialErr == nil {
		return nil, errors.New("the provider host has no address")
	}

	return nil, fmt.Errorf("connecting to the provider failed: %w", dialErr)
}

type callStream = grpc.BidiStreamingClient[dnsgatev1.CallRequest, dnsgatev1.CallResponse]

// relay is the Egress Agent side of one Call stream: it opens the
// connections the Gateway asks for and copies their bytes to and from the
// stream's frames.
type relay struct {
	ctx    context.Context //nolint:containedctx // scoped to one stream
	cancel context.CancelFunc
	stream callStream
	agent  EgressAgent

	sendMu sync.Mutex

	mu     sync.Mutex
	closed bool
	conns  map[uint32]*agentConn
	wg     sync.WaitGroup
}

// agentConn is one relayed connection to a Provider.
type agentConn struct {
	conn net.Conn
	// gatewayDone and providerDone are set once the Gateway, or the
	// Provider, sends no more bytes. The connection is closed once both
	// are.
	gatewayDone, providerDone bool
}

func newRelay(ctx context.Context, cancel context.CancelFunc, stream callStream, agent EgressAgent) *relay {
	return &relay{ctx: ctx, cancel: cancel, stream: stream, agent: agent, conns: map[uint32]*agentConn{}}
}

func (rl *relay) send(msg *dnsgatev1.CallRequest) error {
	rl.sendMu.Lock()
	defer rl.sendMu.Unlock()

	return rl.stream.Send(msg)
}

// open connects to the destination of o, answers it, and relays what the
// Provider sends.
func (rl *relay) open(o *dnsgatev1.RelayOpen) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		return
	}

	rl.wg.Go(func() {
		id := o.GetId()

		conn, err := rl.agent.connect(rl.ctx, o)
		if err != nil {
			_ = rl.send(&dnsgatev1.CallRequest{Message: &dnsgatev1.CallRequest_Opened{
				Opened: &dnsgatev1.RelayOpened{Id: id, Error: err.Error()},
			}})

			return
		}

		c := &agentConn{conn: conn}

		rl.mu.Lock()
		if rl.closed {
			rl.mu.Unlock()

			_ = conn.Close()

			return
		}

		rl.conns[id] = c
		rl.mu.Unlock()

		if rl.send(&dnsgatev1.CallRequest{Message: &dnsgatev1.CallRequest_Opened{Opened: &dnsgatev1.RelayOpened{Id: id}}}) != nil {
			return
		}

		rl.pump(id, c)
	})
}

// pump sends what the Provider sends on c to the Gateway, then a
// RelayClose once the Provider is done or the connection fails.
func (rl *relay) pump(id uint32, c *agentConn) {
	buf := make([]byte, dnsgatev1.RelayFrameSize)

	for {
		n, err := c.conn.Read(buf)
		if n > 0 {
			data := &dnsgatev1.RelayData{Id: id, Data: buf[:n]}
			if rl.send(&dnsgatev1.CallRequest{Message: &dnsgatev1.CallRequest_Data{Data: data}}) != nil {
				return
			}
		}

		if err != nil {
			_ = rl.send(&dnsgatev1.CallRequest{Message: &dnsgatev1.CallRequest_Close{Close: &dnsgatev1.RelayClose{Id: id}}})

			rl.done(id, func(c *agentConn) { c.providerDone = true })

			return
		}
	}
}

// data writes the Gateway's bytes to their connection. It holds the
// stream until the Provider takes them, or for writeTimeout: a failed
// write closes the connection.
func (rl *relay) data(d *dnsgatev1.RelayData) {
	c := rl.conn(d.GetId())
	if c == nil {
		return
	}

	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	if _, err := c.conn.Write(d.GetData()); err != nil {
		_ = c.conn.Close()
	}
}

// closeWrite ends the Gateway's direction of connection id, as a TCP
// half-close where the connection has one.
func (rl *relay) closeWrite(id uint32) {
	rl.done(id, func(c *agentConn) {
		c.gatewayDone = true

		if cw, ok := c.conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})
}

// done marks a direction of connection id done with mark, and closes and
// forgets the connection once both are.
func (rl *relay) done(id uint32, mark func(*agentConn)) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	c := rl.conns[id]
	if c == nil {
		return
	}

	mark(c)

	if c.gatewayDone && c.providerDone {
		_ = c.conn.Close()

		delete(rl.conns, id)
	}
}

func (rl *relay) conn(id uint32) *agentConn {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	return rl.conns[id]
}

// close ends the stream and every relayed connection, and waits until the
// relay's goroutines are done.
func (rl *relay) close() {
	rl.cancel()

	rl.mu.Lock()
	rl.closed = true

	for id, c := range rl.conns {
		_ = c.conn.Close()

		delete(rl.conns, id)
	}
	rl.mu.Unlock()

	rl.wg.Wait()
}
