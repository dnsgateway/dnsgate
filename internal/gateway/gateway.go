// Package gateway serves the Gateway's gRPC API: it reads one Request from
// each Call stream, carries it out and answers with one Response.
package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/token"
)

const (
	tokenIDPrefix   = "tok_"
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
	// MaxAncestors is the most ancestors a Derived Token may have: a
	// chain reaches at most this many Derived Tokens below its Root
	// Token. It keeps tokens, which carry every ancestor's ID, small, and
	// the revocation check of each request short. 0 means 8.
	MaxAncestors int
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
	maxAncestors int
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
		maxAncestors: cfg.MaxAncestors,
		audit:        cfg.Audit,
		log:          cfg.Logger,
		now:          cfg.Now,
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
func (g *Gateway) Call(stream grpc.BidiStreamingServer[dnsgatev1.CallRequest, dnsgatev1.CallResponse]) error {
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

	r := &request{ctx: stream.Context(), id: g.newID(requestIDPrefix)}

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
	default:
		err = invalidRequest("unknown operation")
	}

	if err != nil {
		return err
	}

	return stream.Send(&dnsgatev1.CallResponse{Message: &dnsgatev1.CallResponse_Response{Response: resp}})
}

// request is the context of one Gateway request.
type request struct {
	ctx context.Context //nolint:containedctx // scoped to one request
	id  string
}

// newID returns prefix followed by a new ULID.
func (g *Gateway) newID(prefix string) string {
	return prefix + ulid.MustNew(ulid.Timestamp(g.now()), rand.Reader).String()
}

// writeAudit writes e, stamped with the time and the request ID. A failed
// write is logged and returned, so a caller can withhold what the event
// records.
func (g *Gateway) writeAudit(r *request, e audit.Event) error {
	e.Time = g.now().UTC()
	e.RequestID = r.id

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

func timestamp(d token.NumericDate) *timestamppb.Timestamp {
	return timestamppb.New(d.Time())
}
