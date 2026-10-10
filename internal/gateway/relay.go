package gateway

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"google.golang.org/grpc"
)

// The relay framing is recorded in ADR 0006.
const (
	// relayOpenTimeout bounds how long the Gateway waits for the Egress
	// Agent to answer a RelayOpen.
	relayOpenTimeout = 15 * time.Second
)

// errAgentConnect is the error of a connection the Egress Agent did not
// open: it refused the destination, failed to reach it, or does not
// relay.
var errAgentConnect = errors.New("the egress agent did not connect to the provider")

// errResponseSent is the error of a relay frame sent after the Response,
// which ends the stream.
var errResponseSent = errors.New("the response is sent: the relay sends nothing more")

type callStream = grpc.BidiStreamingServer[dnsgatev1.CallRequest, dnsgatev1.CallResponse]

// relay carries the Agent Egress connections of one Call stream, and its
// Response, which ends them. Its receive loop starts with the first
// connection.
//
// Each connection is a net.Pipe: the Provider's HTTP transport holds one
// end, and the relay copies the other to and from the stream's frames.
// The pipe has no buffer, so a frame for a connection nobody reads holds
// the receive loop, and with it the stream's flow control, until the
// connection is read or closed.
type relay struct {
	stream callStream

	start sync.Once
	// recvDone is closed when the receive loop ends: the client sends
	// nothing more.
	recvDone chan struct{}

	// sendMu serializes Sends. done, under sendMu, is set once the
	// Response is sent: nothing follows it.
	sendMu sync.Mutex
	done   bool

	mu     sync.Mutex
	closed bool
	nextID uint32
	conns  map[uint32]*relayConn
	pumps  sync.WaitGroup
}

// relayConn is one relayed connection.
type relayConn struct {
	id uint32
	// opened receives the error of the Egress Agent's RelayOpened, empty
	// if it connected.
	opened chan string
	// local is the end the Provider's transport uses; remote is the
	// relay's.
	local, remote net.Conn
}

func newRelay(stream callStream) *relay {
	return &relay{stream: stream, recvDone: make(chan struct{}), conns: map[uint32]*relayConn{}}
}

// transport returns a Provider HTTP transport whose connections go through
// the relay. It verifies the Provider's certificate as providerTLS does,
// against roots, and never uses a proxy.
func (rl *relay) transport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		DialContext:           rl.dial,
		TLSClientConfig:       providerTLS(roots),
		TLSHandshakeTimeout:   providerTLSHandshakeTimeout,
		ResponseHeaderTimeout: providerResponseHeaderTimeout,
	}
}

// dial asks the Egress Agent to connect to addr, and returns the relayed
// connection once it has.
func (rl *relay) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}

	rl.start.Do(func() { go rl.receive() })

	local, remote := net.Pipe()
	c := &relayConn{opened: make(chan string, 1), local: local, remote: remote}

	rl.mu.Lock()
	if rl.closed {
		rl.mu.Unlock()

		return nil, errAgentConnect
	}

	rl.nextID++
	c.id = rl.nextID
	rl.conns[c.id] = c
	rl.mu.Unlock()

	if err := rl.open(ctx, c, &dnsgatev1.RelayOpen{Id: c.id, Host: host, Port: uint32(port)}); err != nil {
		rl.drop(c)

		return nil, err
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.closed {
		c.close()

		return nil, errAgentConnect
	}

	rl.pumps.Add(1)

	go rl.pump(c)

	return local, nil
}

// open sends o for c and waits for the Egress Agent to connect. It
// returns ctx's error if ctx ends first, and errAgentConnect if the
// Egress Agent does not connect.
func (rl *relay) open(ctx context.Context, c *relayConn, o *dnsgatev1.RelayOpen) error {
	if rl.send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Open{Open: o}}) != nil {
		return errAgentConnect
	}

	timer := time.NewTimer(relayOpenTimeout)
	defer timer.Stop()

	select {
	case msg := <-c.opened:
		if msg == "" {
			return nil
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-rl.recvDone:
	case <-timer.C:
	}

	return errAgentConnect
}

// receive reads the client's relay frames until the stream ends, then
// ends every connection. A frame for an unknown connection is dropped; a
// frame of any other kind ends the relay.
func (rl *relay) receive() {
	defer close(rl.recvDone)
	defer rl.closeConns()

	for {
		msg, err := rl.stream.Recv()
		if err != nil {
			return
		}

		switch m := msg.GetMessage().(type) {
		case *dnsgatev1.CallRequest_Opened:
			if c := rl.conn(m.Opened.GetId()); c != nil {
				select {
				case c.opened <- m.Opened.GetError():
				default:
				}
			}
		case *dnsgatev1.CallRequest_Data:
			if c := rl.conn(m.Data.GetId()); c != nil {
				// A write fails once the transport closed the connection;
				// its bytes are dropped.
				_, _ = c.remote.Write(m.Data.GetData())
			}
		case *dnsgatev1.CallRequest_Close:
			if c := rl.conn(m.Close.GetId()); c != nil {
				// The transport reads EOF.
				_ = c.remote.Close()
			}
		default:
			return
		}
	}
}

// pump sends what the transport writes on c to the Egress Agent, then a
// RelayClose once c is closed on either side, and forgets c. The
// transport's end stays open until the transport closes it: it reads
// what the relay delivered, then EOF.
func (rl *relay) pump(c *relayConn) {
	defer rl.pumps.Done()
	defer rl.forget(c)
	defer c.remote.Close()

	buf := make([]byte, dnsgatev1.RelayFrameSize)

	for {
		n, err := c.remote.Read(buf)
		if n > 0 {
			data := &dnsgatev1.RelayData{Id: c.id, Data: buf[:n]}
			if rl.send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Data{Data: data}}) != nil {
				return
			}
		}

		if err != nil {
			_ = rl.send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Close{Close: &dnsgatev1.RelayClose{Id: c.id}}})

			return
		}
	}
}

// send sends msg unless the Response is sent.
func (rl *relay) send(msg *dnsgatev1.CallResponse) error {
	rl.sendMu.Lock()
	defer rl.sendMu.Unlock()

	if rl.done {
		return errResponseSent
	}

	return rl.stream.Send(msg)
}

// respond ends every connection and sends resp, the stream's last
// message.
func (rl *relay) respond(resp *dnsgatev1.Response) error {
	rl.close()

	rl.sendMu.Lock()
	defer rl.sendMu.Unlock()

	rl.done = true

	return rl.stream.Send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Response{Response: resp}})
}

// close ends every connection, accepts no new one, and waits until the
// relay sends nothing more for them.
func (rl *relay) close() {
	rl.mu.Lock()
	rl.closed = true
	rl.mu.Unlock()

	rl.closeConns()
	rl.pumps.Wait()
}

func (rl *relay) closeConns() {
	rl.mu.Lock()
	conns := make([]*relayConn, 0, len(rl.conns))

	for _, c := range rl.conns {
		conns = append(conns, c)
	}
	rl.mu.Unlock()

	for _, c := range conns {
		c.close()
	}
}

func (rl *relay) conn(id uint32) *relayConn {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	return rl.conns[id]
}

// drop closes both ends of c and forgets it.
func (rl *relay) drop(c *relayConn) {
	c.close()
	rl.forget(c)
}

// forget forgets c: later frames for it are dropped.
func (rl *relay) forget(c *relayConn) {
	rl.mu.Lock()
	delete(rl.conns, c.id)
	rl.mu.Unlock()
}

func (c *relayConn) close() {
	_ = c.remote.Close()
	_ = c.local.Close()
}
