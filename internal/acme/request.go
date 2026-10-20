package acme

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GatewayTimeout bounds the Gateway round trips of one request, shorter
// than WriteTimeout so the response is written before the server gives up
// on the connection.
const GatewayTimeout = 20 * time.Second

// requestIDPrefix starts the ID each request is logged with.
const requestIDPrefix = "req_"

// reply is a response: its status and JSON body.
type reply struct {
	status int
	body   any
}

type errorBody struct {
	Error string `json:"error"`
}

// The replies both APIs share.
var (
	forbidden     = reply{http.StatusUnauthorized, errorBody{"forbidden"}}
	providerError = reply{http.StatusInternalServerError, errorBody{"provider_error"}}
)

// Reasons a request is refused or fails, logged as its reason. They are
// part of the log format, so they stay stable.
const (
	reasonMalformedJSON      = "malformed JSON"
	reasonNoAPIKey           = "no X-Api-Key"
	reasonNoBasicAuth        = "no Basic auth"
	reasonAPIUserMismatch    = "X-Api-User is not the token's jti"
	reasonNoZone             = "the token's Permissions name no zone, or more than one, for the name"
	reasonTokenRefused       = "the Gateway refused the token"
	reasonPermissionRefused  = "the Gateway refused the Permission or the Egress"
	reasonConfigurationError = "configuration error: the Gateway refused the request; check --ttl against the Provider's TTL range"
	reasonGatewayFailed      = "the Gateway call failed"
)

// outcome is what the log line of one request tells beyond its reply. It
// never holds the Service Token or the challenge value.
type outcome struct {
	// subject is what the request names, its subdomain or fqdn, once it
	// is valid.
	subject string
	// target is the request's Challenge Target, once it is known.
	target Target
	// reason says why the request was refused or failed.
	reason string
	// err is the error of the Gateway call that failed.
	err error
}

// endpoint serves one route: it logs the request headers at debug, carries
// the request out with serve, writes its JSON reply, and logs one line for
// it.
type endpoint struct {
	log *slog.Logger
	// logMsg is the message of the request's log line, the API's name;
	// its header line is logMsg + " headers".
	logMsg string
	// attrs are logged right after the request ID.
	attrs []slog.Attr
	// subjectKey is the field outcome.subject is logged as.
	subjectKey string
	// serve carries the request out and returns its reply, recording in
	// the outcome what the log should tell about it.
	serve func(r *http.Request, o *outcome) reply
}

func (e *endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := requestIDPrefix + ulid.Make().String()

	if e.log.Enabled(r.Context(), slog.LevelDebug) {
		e.log.LogAttrs(r.Context(), slog.LevelDebug, e.logMsg+" headers",
			slog.String("request_id", id), slog.Any("headers", redactedHeaders(r.Header)))
	}

	var o outcome

	rep := e.serve(r, &o)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	_ = json.NewEncoder(w).Encode(rep.body)

	e.logRequest(r.Context(), id, rep, o, time.Since(start))
}

// secretHeaders are the request headers that may carry a secret: the
// Service Token in X-Api-Key or in Basic auth, and the usual credentials a
// proxy or client may add.
var secretHeaders = []string{"X-Api-Key", "Authorization", "Proxy-Authorization", "Cookie"}

// redactedHeaders returns a copy of h with the value of each of
// secretHeaders replaced by its length.
func redactedHeaders(h http.Header) http.Header {
	c := h.Clone()

	for _, k := range secretHeaders {
		for i, v := range c[k] {
			c[k][i] = "[redacted, " + strconv.Itoa(len(v)) + " bytes]"
		}
	}

	return c
}

// logRequest logs the request with ID id, its reply rep and outcome o,
// and how long it took: at info if it succeeded or was refused, at error
// if it failed.
func (e *endpoint) logRequest(ctx context.Context, id string, rep reply, o outcome, took time.Duration) {
	result, level := "ok", slog.LevelInfo
	if b, ok := rep.body.(errorBody); ok {
		result = b.Error
	}

	if rep.status >= http.StatusInternalServerError {
		level = slog.LevelError
	}

	attrs := append([]slog.Attr{slog.String("request_id", id)}, e.attrs...)

	// A subject that is not valid is left out, not logged empty.
	if o.subject != "" {
		attrs = append(attrs, slog.String(e.subjectKey, o.subject))
	}

	attrs = append(attrs,
		slog.String("zone", o.target.Zone),
		slog.String("name", o.target.Name),
		slog.String("result", result),
		slog.Int64("duration_ms", took.Milliseconds()),
	)

	if o.reason != "" {
		attrs = append(attrs, slog.String("reason", o.reason))
	}

	if o.err != nil {
		attrs = append(attrs, slog.String("error", o.err.Error()))
	}

	e.log.LogAttrs(ctx, level, e.logMsg, attrs...)
}

// credentials are what the caller presents: its Service Token, key, and
// the token's ID, user.
type credentials struct {
	user string
	key  string
}

// patcher patches challenge values through the Gateway, presenting the
// caller's Service Token. The Gateway does all the authorization.
type patcher struct {
	gateway *client.Client
	// egress is the Egress every write asks for.
	egress dnsgatev1.Egress
}

// patch patches TXT at target with the caller's credentials cred, under
// GatewayTimeout: it inspects cred.key, checks cred.user against its jti, takes target's zone from its Permissions if
// target names none, and sends the PatchRecord that change fills in. It
// returns false with the reply to send if any of that refuses or fails,
// recording in o the resolved target and why.
func (p patcher) patch(ctx context.Context, o *outcome, cred credentials, target Target,
	change func(*dnsgatev1.PatchRecordRequest),
) (reply, bool) {
	ctx, cancel := context.WithTimeout(ctx, GatewayTimeout)
	defer cancel()

	info, err := p.gateway.InspectToken(ctx, cred.key)
	if err != nil {
		return gatewayFailure(o, err), false
	}

	if info.GetJti() != cred.user {
		o.reason = reasonAPIUserMismatch

		return forbidden, false
	}

	target, ok := target.resolve(info.GetPermissions())
	if !ok {
		o.reason = reasonNoZone

		return forbidden, false
	}

	o.target = target

	req := &dnsgatev1.PatchRecordRequest{
		Token:  cred.key,
		Egress: p.egress,
		Zone:   target.Zone,
		Name:   target.Name,
		Type:   "TXT",
	}
	change(req)

	if _, err := p.gateway.PatchRecord(ctx, req); err != nil {
		return gatewayFailure(o, err), false
	}

	return reply{}, true
}

// txtValue is the record of a challenge value, as txtString gives it.
func txtValue(value string) []*dnsgatev1.RecordValue {
	return []*dnsgatev1.RecordValue{{Value: txtString(value)}}
}

// txtString is a challenge value in TXT presentation form; a challenge
// value needs no escaping.
func txtString(value string) string {
	return `"` + value + `"`
}

// gatewayFailure returns the reply to a failed Gateway call, recording
// err in o. The Gateway refusing the token, a Permission or the Egress is
// forbidden. Anything else is a provider error: the Provider failing,
// its refusing the Provider Credential included, the Gateway out of reach
// or timing out, or the Gateway refusing the request the daemon built
// from its configuration. The Gateway's error messages never quote what
// the client sent, so err holds no secret.
func gatewayFailure(o *outcome, err error) reply {
	o.err = err

	st := status.Convert(err)

	switch {
	case st.Code() == codes.Unauthenticated:
		o.reason = reasonTokenRefused

		return forbidden
	case st.Code() == codes.PermissionDenied &&
		dnsgatev1.ErrorDetail(st).GetCategory() != dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER:
		o.reason = reasonPermissionRefused

		return forbidden
	case st.Code() == codes.InvalidArgument:
		// The daemon checked the values the client sent, so the rest,
		// its configuration, is at fault: the TTL most likely.
		o.reason = reasonConfigurationError

		return providerError
	default:
		o.reason = reasonGatewayFailed

		return providerError
	}
}

// decodeJSON decodes body into v: one JSON object and nothing after it.
// A body past MaxBodyBytes fails to decode too.
func decodeJSON(body io.Reader, v any) error {
	dec := json.NewDecoder(body)
	if err := dec.Decode(v); err != nil {
		return err
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON object")
	}

	return nil
}

// challengeValueLen is the length of an ACME DNS-01 challenge value: a
// SHA-256 digest in unpadded base64url.
const challengeValueLen = 43

// isChallengeValue reports whether s has the shape of an ACME DNS-01
// challenge value: exactly 43 of [A-Za-z0-9_-].
func isChallengeValue(s string) bool {
	if len(s) != challengeValueLen {
		return false
	}

	for _, c := range []byte(s) {
		if !isAlnum(c) && c != '-' && c != '_' {
			return false
		}
	}

	return true
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}
