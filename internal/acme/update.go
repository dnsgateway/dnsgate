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

// GatewayTimeout bounds the Gateway round trips of one /update, shorter
// than WriteTimeout so the response is written before the server gives up
// on the connection.
const GatewayTimeout = 20 * time.Second

// requestIDPrefix starts the ID each /update is logged with.
const requestIDPrefix = "req_"

// updateRequest is the body of an acme-dns POST /update.
type updateRequest struct {
	Subdomain string `json:"subdomain"`
	TXT       string `json:"txt"`
}

// reply is an acme-dns response: its status and JSON body.
type reply struct {
	status int
	body   any
}

type txtBody struct {
	TXT string `json:"txt"`
}

type errorBody struct {
	Error string `json:"error"`
}

var (
	forbidden     = reply{http.StatusUnauthorized, errorBody{"forbidden"}}
	providerError = reply{http.StatusInternalServerError, errorBody{"provider_error"}}
	badSubdomain  = reply{http.StatusBadRequest, errorBody{"bad_subdomain"}}
	badTXT        = reply{http.StatusBadRequest, errorBody{"bad_txt"}}
)

// Reasons an /update is refused or fails, logged as its reason. They are
// part of the log format, so they stay stable.
const (
	reasonMalformedJSON      = "malformed JSON"
	reasonNoAPIKey           = "no X-Api-Key"
	reasonAPIUserMismatch    = "X-Api-User is not the token's jti"
	reasonNoZone             = "the token's Permissions name no zone, or more than one, for the name"
	reasonTokenRefused       = "the Gateway refused the token"
	reasonPermissionRefused  = "the Gateway refused the Permission or the Egress"
	reasonConfigurationError = "configuration error: the Gateway refused the request; check --ttl against the Provider's TTL range"
	reasonGatewayFailed      = "the Gateway call failed"
)

// updater serves POST /update: it adds the TXT value at the subdomain's
// Challenge Target through the Gateway, presenting the caller's Service
// Token. The Gateway does all the authorization.
type updater struct {
	gateway *client.Client
	targets ChallengeMap
	ttl     uint32
	egress  dnsgatev1.Egress
	log     *slog.Logger
}

// outcome is what the log line of one /update tells beyond its reply. It
// never holds the Service Token or the TXT value.
type outcome struct {
	// subdomain is the request's subdomain, once it is a valid label.
	subdomain string
	// target is the subdomain's Challenge Target, once it is known.
	target Target
	// reason says why the request was refused or failed.
	reason string
	// err is the error of the Gateway call that failed.
	err error
}

func (u *updater) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := requestIDPrefix + ulid.Make().String()

	if u.log.Enabled(r.Context(), slog.LevelDebug) {
		u.log.LogAttrs(r.Context(), slog.LevelDebug, "update headers",
			slog.String("request_id", id), slog.Any("headers", redactedHeaders(r.Header)))
	}

	var o outcome

	rep := u.update(r, &o)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rep.status)
	_ = json.NewEncoder(w).Encode(rep.body)

	u.logUpdate(r.Context(), id, rep, o, time.Since(start))
}

// secretHeaders are the request headers that may carry a secret: the
// Service Token in X-Api-Key, and the usual credentials a proxy or client
// may add.
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

// logUpdate logs the /update with request ID id, its reply rep and
// outcome o, and how long it took: at info if it succeeded or was
// refused, at error if it failed.
func (u *updater) logUpdate(ctx context.Context, id string, rep reply, o outcome, took time.Duration) {
	result, level := "ok", slog.LevelInfo
	if e, ok := rep.body.(errorBody); ok {
		result = e.Error
	}

	if rep.status >= http.StatusInternalServerError {
		level = slog.LevelError
	}

	attrs := []slog.Attr{
		slog.String("request_id", id),
		slog.String("subdomain", o.subdomain),
		slog.String("zone", o.target.Zone),
		slog.String("name", o.target.Name),
		slog.String("result", result),
		slog.Int64("duration_ms", took.Milliseconds()),
	}

	if o.reason != "" {
		attrs = append(attrs, slog.String("reason", o.reason))
	}

	if o.err != nil {
		attrs = append(attrs, slog.String("error", o.err.Error()))
	}

	u.log.LogAttrs(ctx, level, "update", attrs...)
}

// update carries out the /update in r and returns the reply for it,
// recording in o what the log should tell about it. The local checks
// come first, so a request they refuse never reaches the Gateway.
func (u *updater) update(r *http.Request, o *outcome) reply {
	req, err := decodeUpdate(r.Body)
	if err != nil {
		o.reason = reasonMalformedJSON

		return forbidden
	}

	// A subdomain not in the Challenge Map is taken as the certificate
	// domain. One that is neither a DNS label nor a domain name is left out
	// of the log: it may be anything, a secret pasted in the wrong field
	// included.
	target, ok := u.targets[req.Subdomain]
	if !ok {
		target, ok = domainTarget(req.Subdomain)
	}

	if !ok {
		return badSubdomain
	}

	o.subdomain = req.Subdomain

	if !isChallengeValue(req.TXT) {
		return badTXT
	}

	o.target = target

	key := r.Header.Get("X-Api-Key")
	if key == "" {
		o.reason = reasonNoAPIKey

		return forbidden
	}

	ctx, cancel := context.WithTimeout(r.Context(), GatewayTimeout)
	defer cancel()

	info, err := u.gateway.InspectToken(ctx, key)
	if err != nil {
		return gatewayFailure(o, err)
	}

	if info.GetJti() != r.Header.Get("X-Api-User") {
		o.reason = reasonAPIUserMismatch

		return forbidden
	}

	target, ok = target.resolve(info.GetPermissions())
	if !ok {
		o.reason = reasonNoZone

		return forbidden
	}

	o.target = target

	_, err = u.gateway.PatchRecord(ctx, &dnsgatev1.PatchRecordRequest{
		Token:  key,
		Egress: u.egress,
		Zone:   target.Zone,
		Name:   target.Name,
		Type:   "TXT",
		Ttl:    u.ttl,
		// The value in TXT presentation form; a challenge value needs no
		// escaping.
		Add: []*dnsgatev1.RecordValue{{Value: `"` + req.TXT + `"`}},
	})
	if err != nil {
		return gatewayFailure(o, err)
	}

	return reply{http.StatusOK, txtBody{req.TXT}}
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
		// The daemon checked the one value the client sent, so the rest,
		// its configuration, is at fault: the TTL most likely.
		o.reason = reasonConfigurationError

		return providerError
	default:
		o.reason = reasonGatewayFailed

		return providerError
	}
}

// decodeUpdate decodes the /update request in body: one JSON object and
// nothing after it. A body past MaxBodyBytes fails to decode too.
func decodeUpdate(body io.Reader) (updateRequest, error) {
	var req updateRequest

	dec := json.NewDecoder(body)
	if err := dec.Decode(&req); err != nil {
		return req, err
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return req, errors.New("data after the JSON object")
	}

	return req, nil
}

// isLabel reports whether s is a single DNS label, as an acme-dns
// subdomain must be: 1 to 63 of [A-Za-z0-9-], not starting or ending
// with a hyphen.
func isLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}

	for _, c := range []byte(s) {
		if !isAlnum(c) && c != '-' {
			return false
		}
	}

	return true
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
