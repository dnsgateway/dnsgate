// Package gateway serves the Gateway's gRPC API: it reads one Request from
// each Call stream, carries it out and answers with one Response.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/revocation"
	"github.com/dnsgateway/dnsgate/internal/token"
)

const (
	requestIDPrefix = "req_"

	// defaultMaxAncestors is the maximum chain depth of a Config that
	// sets none.
	defaultMaxAncestors = 8
)

// Config is what a Gateway is built from.
type Config struct {
	// Keys signs, encrypts and opens Service Tokens.
	Keys keys.Source
	// BootstrapSecret authorizes Onboarding.
	BootstrapSecret token.Secret
	// Audit receives the audit events.
	Audit *audit.Log
	// Providers builds the Provider of a token from its Provider
	// Credential; nil means provider.Registry().
	Providers dnsprovider.Registry
	// EgressTransport sends the Providers' requests through Gateway
	// Egress. nil means each Provider's own transport, which verifies
	// TLS strictly against the system roots and bounds each request;
	// a transport given here brings its own TLS settings and timeouts.
	// Tests point it at a fake Provider API.
	EgressTransport http.RoundTripper
	// AgentEgressRootCAs are the CA certificates the Gateway verifies
	// a Provider's certificate against through Agent Egress; nil means
	// the system's. The Provider's hostname is always verified.
	AgentEgressRootCAs *x509.CertPool
	// MaxAncestors is the most ancestors a Derived Token may have: a
	// chain reaches at most this many Derived Tokens below its Root
	// Token. It keeps tokens, which carry every ancestor's ID, small, and
	// the revocation check of each request short. 0 means 8.
	MaxAncestors int
	// RevokedIDs is the revocation store, holding the revoked token IDs;
	// it is required. Every request is refused whose token, or one of its
	// ancestors, is revoked.
	RevokedIDs revocation.Store
	// Logger receives operational logs; nil discards them.
	Logger *slog.Logger
	// Now is the Gateway's clock; nil means time.Now.
	Now func() time.Time
}

// Gateway implements the GatewayService.
type Gateway struct {
	dnsgatev1.UnimplementedGatewayServiceServer

	codec        *token.Codec
	bootstrap    token.Secret
	providers    dnsprovider.Registry
	egress       http.RoundTripper
	agentRoots   *x509.CertPool
	maxAncestors int
	revokedIDs   revocation.Store
	audit        *audit.Log
	log          *slog.Logger
	now          func() time.Time
}

var _ dnsgatev1.GatewayServiceServer = (*Gateway)(nil)

// New returns a Gateway built from cfg.
func New(cfg Config) *Gateway {
	g := &Gateway{
		bootstrap:    cfg.BootstrapSecret,
		providers:    cfg.Providers,
		egress:       cfg.EgressTransport,
		agentRoots:   cfg.AgentEgressRootCAs,
		maxAncestors: cfg.MaxAncestors,
		revokedIDs:   cfg.RevokedIDs,
		audit:        cfg.Audit,
		log:          cfg.Logger,
		now:          cfg.Now,
	}

	if g.revokedIDs == nil {
		panic("gateway: Config.RevokedIDs is required")
	}

	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}

	if g.maxAncestors <= 0 {
		g.maxAncestors = defaultMaxAncestors
	}

	if g.now == nil {
		g.now = time.Now
	}

	if g.providers == nil {
		g.providers = provider.Registry()
	}

	g.codec = token.NewCodec(cfg.Keys, token.WithClock(g.now))

	return g
}

// Call implements GatewayService.Call.
func (g *Gateway) Call(stream grpc.BidiStreamingServer[dnsgatev1.CallRequest, dnsgatev1.CallResponse]) (err error) {
	// The request is logged however it ends, even before the stream has
	// carried a `dnsgatev1.Request`, under the ID its audit events carry.
	r := &request{ctx: stream.Context(), id: g.newID(requestIDPrefix), start: g.now()}
	defer func() { g.logRequest(r, err) }()

	msg, err := stream.Recv()
	if errors.Is(err, io.EOF) {
		return invalidRequest("the stream ended before a request")
	}

	if err != nil {
		return err
	}

	req := msg.GetRequest()
	if req == nil {
		return invalidRequest("the first message of a stream must be a request")
	}

	r.operation = operation(req)
	r.relay = newRelay(stream)

	defer r.relay.close()

	var resp *dnsgatev1.Response

	switch op := req.GetOperation().(type) {
	case *dnsgatev1.Request_Onboard:
		resp, err = g.onboard(r, op.Onboard)
	case *dnsgatev1.Request_InspectToken:
		resp, err = g.inspectToken(r, op.InspectToken)
	case *dnsgatev1.Request_CreateToken:
		resp, err = g.createToken(r, op.CreateToken)
	case *dnsgatev1.Request_ResealToken:
		resp, err = g.resealToken(r, op.ResealToken)
	case *dnsgatev1.Request_RevokeToken:
		resp, err = g.revokeToken(r, op.RevokeToken)
	case *dnsgatev1.Request_ListZones:
		resp, err = g.listZones(r, op.ListZones)
	case *dnsgatev1.Request_GetZone:
		resp, err = g.getZone(r, op.GetZone)
	case *dnsgatev1.Request_ListRecords:
		resp, err = g.listRecords(r, op.ListRecords)
	case *dnsgatev1.Request_GetRecord:
		resp, err = g.getRecord(r, op.GetRecord)
	case *dnsgatev1.Request_CreateRecord:
		resp, err = g.createRecord(r, op.CreateRecord)
	case *dnsgatev1.Request_UpdateRecord:
		resp, err = g.updateRecord(r, op.UpdateRecord)
	case *dnsgatev1.Request_PatchRecord:
		resp, err = g.patchRecord(r, op.PatchRecord)
	case *dnsgatev1.Request_DeleteRecord:
		resp, err = g.deleteRecord(r, op.DeleteRecord)
	default:
		err = invalidRequest("unknown operation")
	}

	if err != nil {
		return err
	}

	return r.relay.respond(resp)
}

// request is the context of one Gateway request.
type request struct {
	ctx context.Context //nolint:containedctx // scoped to one request
	id  string
	// operation is the name of the operation the request asks for, such
	// as "list_zones", or "" until the stream has carried a request that
	// names one.
	operation string
	// start is when the Gateway opened the request's stream, on the
	// Gateway's clock. Its request line and its audit events measure
	// their duration from it, so they agree; a test clock stands in for
	// the Gateway's.
	start time.Time
	// relay carries the request's Agent Egress connections, inside its
	// stream, and sends its Response.
	relay *relay
}

// logRequest logs, at debug, the request r, which ended with err. Like
// an audit event, the line holds only fields the Gateway produced, never
// what the client sent.
func (g *Gateway) logRequest(r *request, err error) {
	addr := ""
	if p, ok := peer.FromContext(r.ctx); ok && p.Addr != nil {
		addr = p.Addr.String()
	}

	method, _ := grpc.Method(r.ctx)

	g.log.Debug("request",
		"method", method,
		"operation", r.operation,
		"request_id", r.id,
		"peer", addr,
		"duration_ms", g.now().Sub(r.start).Milliseconds(),
		"code", status.Code(err).String(),
	)
}

// operation returns the name of the operation req asks for, such as
// "list_zones", or "" if it asks for none.
func operation(req *dnsgatev1.Request) string {
	m := req.ProtoReflect()

	f := m.WhichOneof(m.Descriptor().Oneofs().ByName("operation"))
	if f == nil {
		return ""
	}

	return string(f.Name())
}

// newID returns prefix followed by a new ULID.
func (g *Gateway) newID(prefix string) string {
	return prefix + ulid.MustNew(ulid.Timestamp(g.now()), rand.Reader).String()
}

// writeAudit writes e, stamped with the time, the request ID and how long
// the request has taken. A failed
// write is logged and returned, so a caller can withhold what the event
// records.
func (g *Gateway) writeAudit(r *request, e audit.Event) error {
	e.Time = g.now().UTC()
	e.RequestID = r.id
	e.DurationMS = g.now().Sub(r.start).Milliseconds()

	err := g.audit.Write(e)
	if err != nil {
		g.log.Error("audit event lost", "request_id", r.id, "event", e.Event, "error", err)
	}

	return err
}

// deny audits a refused request as e, denied with the category of err,
// and returns err, the Gateway error the client gets. The request is
// refused even if its event is lost.
func (g *Gateway) deny(r *request, e audit.Event, err error) error {
	e.Result = audit.ResultDenied
	e.Category = category(err)

	_ = g.writeAudit(r, e)

	return err
}

// failed audits an allowed request that failed as e, with the category
// of err, and returns err, the Gateway error the client gets. The request
// fails even if its event is lost.
func (g *Gateway) failed(r *request, e audit.Event, err error) error {
	e.Result = audit.ResultFailed
	e.Category = category(err)

	_ = g.writeAudit(r, e)

	return err
}

func timestamp(d token.NumericDate) *timestamppb.Timestamp {
	return timestamppb.New(d.Time())
}
