// Package gateway serves the Gateway's gRPC API: it reads one Request from
// each Call stream, carries it out and answers with one Response.
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"
	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	// ProviderRootCAs are the CA certificates the Gateway verifies a
	// Provider's certificate against, through either Egress; nil means
	// the system's. The Provider's hostname is always verified, and
	// nothing turns that verification off.
	ProviderRootCAs *x509.CertPool
	// GatewayEgressDial opens the connections of Gateway Egress to a
	// Provider's address; nil means the network's. It picks only where a
	// connection goes: the Gateway's own transport runs TLS over it,
	// verified as ProviderRootCAs says. Tests point it at a fake Provider
	// API.
	GatewayEgressDial func(ctx context.Context, network, addr string) (net.Conn, error)
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

	codec     *token.Codec
	bootstrap token.Secret
	providers dnsprovider.Registry
	// gatewayEgress is the Provider transport of Gateway Egress.
	gatewayEgress *http.Transport
	// providerRoots are the CAs a Provider's certificate is verified
	// against; nil means the system's.
	providerRoots *x509.CertPool
	maxAncestors  int
	revokedIDs    revocation.Store
	audit         *audit.Log
	log           *slog.Logger
	now           func() time.Time
}

var _ dnsgatev1.GatewayServiceServer = (*Gateway)(nil)

// New returns a Gateway built from cfg.
func New(cfg Config) *Gateway {
	g := &Gateway{
		bootstrap:     cfg.BootstrapSecret,
		providers:     cfg.Providers,
		gatewayEgress: gatewayEgressTransport(cfg.GatewayEgressDial, cfg.ProviderRootCAs),
		providerRoots: cfg.ProviderRootCAs,
		maxAncestors:  cfg.MaxAncestors,
		revokedIDs:    cfg.RevokedIDs,
		audit:         cfg.Audit,
		log:           cfg.Logger,
		now:           cfg.Now,
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

	// A panic fails its request alone, with an internal error, and is
	// audited as such.
	defer func() {
		if p := recover(); p != nil {
			g.logPanic(r, p)

			err = g.auditPanic(r)
		}
	}()

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
	// event, if set, is the audit event of the request as far as it is
	// filled in, so that a panic can still audit what it knew.
	event *audit.Event
	// audited is set once the request's audit event is written.
	audited bool
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

// logPanic logs the panic p of request r, with the stack it unwound. The
// panic value may quote anything the request held, a secret included,
// so it is logged by its type alone, unless it is a runtime error, whose
// message the Go runtime writes from types and numbers. A stack trace
// shows a function's arguments as machine words, never what a string
// holds.
func (g *Gateway) logPanic(r *request, p any) {
	value := fmt.Sprintf("%T", p)
	if rerr, ok := p.(runtime.Error); ok {
		value = rerr.Error()
	}

	g.log.Error("request panicked",
		"request_id", r.id,
		"operation", r.operation,
		"panic", value,
		"stack", string(debug.Stack()),
	)
}

// operationEvents names the audit event of each operation.
var operationEvents = map[string]audit.Name{
	"onboard":       audit.EventOnboard,
	"inspect_token": audit.EventTokenInspect,
	"create_token":  audit.EventTokenCreate,
	"reseal_token":  audit.EventTokenReseal,
	"revoke_token":  audit.EventTokenRevoke,
	"list_zones":    audit.EventZonesList,
	"get_zone":      audit.EventZonesGet,
	"list_records":  audit.EventRecordsList,
	"get_record":    audit.EventRecordsGet,
	"create_record": audit.EventRecordsCreate,
	"update_record": audit.EventRecordsUpdate,
	"patch_record":  audit.EventRecordsPatch,
	"delete_record": audit.EventRecordsDelete,
}

// auditPanic audits the panicked request r as failed, internal, unless
// its event is written already or its operation is unknown, and returns
// the internal error the client gets. The event is the one the request
// was filling in, if any: a mutation that panics after the Provider
// changed records is audited with what it knew. A write that panics too
// is logged as a lost event.
func (g *Gateway) auditPanic(r *request) (err error) {
	err = internal()

	if r.audited {
		return err
	}

	e := audit.Event{Event: operationEvents[r.operation]}
	if r.event != nil {
		e = *r.event
	}

	if e.Event == "" {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			g.log.Error("audit event lost", "request_id", r.id, "event", e.Event, "panic", fmt.Sprintf("%T", p))
		}
	}()

	return g.failed(r, e, err)
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
	r.audited = true

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
