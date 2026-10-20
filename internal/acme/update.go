package acme

import (
	"net/http"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

// updateRequest is the body of an acme-dns POST /update.
type updateRequest struct {
	Subdomain string `json:"subdomain"`
	TXT       string `json:"txt"`
}

type txtBody struct {
	TXT string `json:"txt"`
}

var (
	badSubdomain = reply{http.StatusBadRequest, errorBody{"bad_subdomain"}}
	badTXT       = reply{http.StatusBadRequest, errorBody{"bad_txt"}}
)

// updater serves POST /update: it adds the TXT value at the subdomain's
// Challenge Target through the Gateway, presenting the caller's Service
// Token. The Gateway does all the authorization.
type updater struct {
	writer

	targets ChallengeMap
	ttl     uint32
}

// update carries out the /update in r and returns the reply for it,
// recording in o what the log should tell about it. The local checks
// come first, so a request they refuse never reaches the Gateway.
func (u *updater) update(r *http.Request, o *outcome) reply {
	var req updateRequest
	if err := decodeJSON(r.Body, &req); err != nil {
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

	o.subject = req.Subdomain

	if !isChallengeValue(req.TXT) {
		return badTXT
	}

	o.target = target

	key := r.Header.Get("X-Api-Key")
	if key == "" {
		o.reason = reasonNoAPIKey

		return forbidden
	}

	if rep, ok := u.patch(r.Context(), o, key, r.Header.Get("X-Api-User"), target,
		func(p *dnsgatev1.PatchRecordRequest) {
			p.Ttl = u.ttl
			p.Add = txtValue(req.TXT)
		}); !ok {
		return rep
	}

	return reply{http.StatusOK, txtBody{req.TXT}}
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
