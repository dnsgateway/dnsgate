package acme

import (
	"log/slog"
	"net/http"
	"strings"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"

	"github.com/dnsgateway/dnsgate/internal/dnsname"
)

// acmeproxyRequest is the body of an acmeproxy POST /present or
// /cleanup, and of its success reply.
type acmeproxyRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

var (
	badRequest = reply{http.StatusBadRequest, errorBody{"bad_request"}}
	badFQDN    = reply{http.StatusBadRequest, errorBody{"bad_fqdn"}}
	badValue   = reply{http.StatusBadRequest, errorBody{"bad_value"}}
)

// acmeproxy serves one call of the acmeproxy API: it changes the value at
// the fqdn, the Challenge Target, through the Gateway, presenting the
// Service Token the caller gives as the Basic auth password, its jti as
// the username. The Gateway does all the authorization.
type acmeproxy struct {
	patcher

	// change puts the change of the call, adding or removing value, into
	// the PatchRecord request.
	change func(req *dnsgatev1.PatchRecordRequest, value string)
}

// acmeproxyEndpoint returns the endpoint that serves p, logged with
// action.
func acmeproxyEndpoint(log *slog.Logger, action string, p *acmeproxy) *endpoint {
	return &endpoint{
		log:        log,
		logMsg:     "acmeproxy",
		attrs:      []slog.Attr{slog.String("action", action)},
		subjectKey: "fqdn",
		serve:      p.serve,
	}
}

// present adds the value with TTL ttl, keeping the values already there.
func present(ttl uint32) func(*dnsgatev1.PatchRecordRequest, string) {
	return func(req *dnsgatev1.PatchRecordRequest, value string) {
		req.Ttl = ttl
		req.Add = txtValue(value)
	}
}

// serve carries out the call in r and returns the reply for it, recording
// in o what the log should tell about it. The local checks come first, so
// a request they refuse never reaches the Gateway.
func (p *acmeproxy) serve(r *http.Request, o *outcome) reply {
	var req acmeproxyRequest
	if err := decodeJSON(r.Body, &req); err != nil {
		o.reason = reasonMalformedJSON

		return badRequest
	}

	// An fqdn that is not a domain name is left out of the log: it may be
	// anything, a secret pasted in the wrong field included.
	target, ok := fqdnTarget(req.FQDN)
	if !ok {
		return badFQDN
	}

	o.subject = req.FQDN

	if !isChallengeValue(req.Value) {
		return badValue
	}

	o.target = target

	user, key, ok := r.BasicAuth()
	if !ok || key == "" {
		o.reason = reasonNoBasicAuth

		return forbidden
	}

	if rep, ok := p.patch(r.Context(), o, credentials{user: user, key: key}, target,
		func(pr *dnsgatev1.PatchRecordRequest) { p.change(pr, req.Value) }); !ok {
		return rep
	}

	return reply{http.StatusOK, req}
}

// fqdnTarget returns the Challenge Target, without a zone, that fqdn
// names as an absolute name, and whether fqdn is a domain name at all: at
// most 253 characters and two labels or more, each a DNS label that may
// start with underscores, case and a trailing dot ignored. A single label
// is never read as relative.
func fqdnTarget(fqdn string) (Target, bool) {
	name := dnsname.Zone(fqdn)
	if len(name) > maxDomainLen || !strings.Contains(name, ".") {
		return Target{}, false
	}

	for l := range strings.SplitSeq(name, ".") {
		// The whole label counts against 63, its leading underscores
		// included, which isLabel does not see.
		if len(l) > 63 || !isLabel(strings.TrimLeft(l, "_")) {
			return Target{}, false
		}
	}

	return Target{Name: name + "."}, true
}
