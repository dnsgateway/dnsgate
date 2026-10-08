// Package gateway serves the Gateway's gRPC API: it reads one Request from
// each Call stream, carries it out and answers with one Response.
package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/token"
)

const (
	tokenIDPrefix   = "tok_"
	requestIDPrefix = "req_"
)

// Config is what a Gateway is built from.
type Config struct {
	// Keys signs, encrypts and opens Service Tokens.
	Keys keys.Source
	// BootstrapSecret authorizes Onboarding.
	BootstrapSecret token.Secret
	// Audit receives the audit events.
	Audit *audit.Log
	// Logger receives operational logs; nil discards them.
	Logger *slog.Logger
	// Now is the Gateway's clock; nil means time.Now.
	Now func() time.Time
}

// Gateway implements the GatewayService.
type Gateway struct {
	dnsgatev1.UnimplementedGatewayServiceServer

	codec     *token.Codec
	bootstrap token.Secret
	audit     *audit.Log
	log       *slog.Logger
	now       func() time.Time
}

var _ dnsgatev1.GatewayServiceServer = (*Gateway)(nil)

// New returns a Gateway built from cfg.
func New(cfg Config) *Gateway {
	g := &Gateway{
		bootstrap: cfg.BootstrapSecret,
		audit:     cfg.Audit,
		log:       cfg.Logger,
		now:       cfg.Now,
	}

	if g.log == nil {
		g.log = slog.New(slog.DiscardHandler)
	}

	if g.now == nil {
		g.now = time.Now
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

// deny audits a refused request as event and returns err, the Gateway
// error the client gets. The request is refused even if its event is lost.
func (g *Gateway) deny(r *request, event audit.Name, err error) error {
	_ = g.writeAudit(r, audit.Event{Event: event, Result: audit.ResultDenied, Category: category(err)})

	return err
}

func timestamp(d token.NumericDate) *timestamppb.Timestamp {
	return timestamppb.New(d.Time())
}
