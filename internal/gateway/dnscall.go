package gateway

import (
	"net/http"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// dnsCall is a zone or record request that passed the Gateway's checks,
// with the Provider built for it. Its audit event fills in as the request
// passes each check.
type dnsCall struct {
	*request

	event audit.Event

	claims token.Claims
	// perm is what the request asks, as Permissions see it, through the
	// Egress it goes through.
	perm     permission.Request
	provider dnsprovider.Provider
	// factory is the Factory of the token's Provider type, which declares
	// the TTLs and Record Extras its Providers take.
	factory dnsprovider.Factory
}

// tokenRequest is a zone or record request: it presents a Service Token
// and may ask for an Egress.
type tokenRequest interface {
	GetToken() string
	GetEgress() dnsgatev1.Egress
}

// startDNSCall takes a zone or record request through the Gateway's checks
// in the documented order: open the token (decrypt, verify, check iss,
// aud, nbf and exp, then check it and its ancestors are not revoked),
// check the request's form with check, if given, check its Permissions
// and Egress, and only then build the Provider from the Provider
// Credential. check puts the zone, record name and type of pr in
// the form the Gateway compares, emptying any that fails. A refused
// request is audited, and startDNSCall returns the Gateway error the
// client gets. Its event names, from the start, the zone, record name and
// type that passed check, so even a token that does not open is audited
// with what it asked for; one that failed may hold anything, and stays
// out.
func (g *Gateway) startDNSCall(r *request, event audit.Name, req tokenRequest, pr permission.Request, check func(*permission.Request) error) (*dnsCall, error) {
	var formErr error
	if check != nil {
		formErr = check(&pr)
	}

	c := &dnsCall{
		request: r,
		event: audit.Event{
			Event: event, Verb: string(pr.Verb), Zone: pr.Zone, RecordName: pr.Name, RecordType: pr.Type,
		},
	}
	r.event = &c.event

	claims, err := g.openToken(r, c.event, req.GetToken())
	if err != nil {
		return nil, err
	}

	c.claims = claims
	c.event.ServiceAccount, c.event.TokenID, c.event.Provider = claims.Subject, claims.ID, claims.Provider

	if formErr != nil {
		return nil, g.deny(r, c.event, formErr)
	}

	if err := g.authorize(c, req.GetEgress(), pr); err != nil {
		return nil, err
	}

	if err := g.connect(c); err != nil {
		return nil, err
	}

	return c, nil
}

// openToken opens the Service Token tok presented with a request: it
// decrypts and verifies it, checks its iss, aud, nbf and exp, then checks
// that neither it nor any of its ancestors is revoked. A token that does
// not open, or is revoked, is audited as event, denied, and openToken
// returns the Gateway error the client gets.
func (g *Gateway) openToken(r *request, event audit.Event, tok string) (token.Claims, error) {
	claims, err := g.codec.Open(r.ctx, tok)
	if err != nil {
		return token.Claims{}, g.deny(r, event, unauthenticated("invalid service token"))
	}

	if err := g.checkRevoked(r, event, claims); err != nil {
		return token.Claims{}, err
	}

	return claims, nil
}

// checkRevoked refuses a token that is revoked, or whose ancestor is:
// revoking a token revokes every token derived from it. A refused token
// is audited as event, denied. If the store cannot answer, the token is
// refused too.
func (g *Gateway) checkRevoked(r *request, event audit.Event, claims token.Claims) error {
	revoked, err := g.revokedIDs.AnyRevoked(r.ctx, append([]string{claims.ID}, claims.Ancestors...))

	switch {
	case err != nil:
		g.log.Error("checking revoked tokens", "request_id", r.id, "error", err)

		return g.deny(r, event, internal())
	case revoked:
		return g.deny(r, event, unauthenticated("revoked service token"))
	}

	return nil
}

// authorize checks that the token's Permissions allow pr through the
// requested Egress, or through the Egress chosen for it, which becomes
// the call's: Gateway Egress where they allow it, else Agent Egress. A
// token that allows only Agent Egress never falls back to Gateway Egress.
func (g *Gateway) authorize(c *dnsCall, requested dnsgatev1.Egress, pr permission.Request) error {
	name, ok := permission.EgressFromAPI(requested)
	if !ok {
		return g.deny(c.request, c.event, invalidRequest("unknown egress"))
	}

	c.event.RequestedEgress = string(name)
	pr.Egress = name

	egress, ok := permission.ChooseEgress(c.claims.Permissions, pr)
	if !ok {
		return g.deny(c.request, c.event, permissionDenied("the token's permissions do not allow the request"))
	}

	pr.Egress = egress
	c.perm = pr
	c.event.Egress = string(egress)

	return nil
}

// connect builds the token's Provider from its Provider Credential, its
// requests sent through the call's Egress, always with the Gateway's own
// transport, which verifies the Provider's certificate: for Gateway
// Egress, from the Gateway; for Agent Egress, relayed by the client inside
// the request's stream, with TLS to the Provider still ending on the
// Gateway. The plaintext credential lives on only inside
// the Provider, which is dropped with the call. A failed build is logged
// by its reason alone: the Provider's error may quote the credential.
func (g *Gateway) connect(c *dnsCall) error {
	var transport http.RoundTripper = g.gatewayEgress
	if c.perm.Egress == permission.EgressAgent {
		transport = c.relay.transport(g.providerRoots)
	}

	name := c.claims.Provider

	p, err := g.providers.New(name, provider.CredentialFields(name, c.claims.Credential.Value.Reveal()),
		dnsprovider.WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		reason := "provider_rejected_credential"
		if _, ok := g.providers[name]; !ok {
			reason = "unknown_provider"
		}

		g.log.Error("building provider", "request_id", c.id, "provider", name, "reason", reason)

		return g.fail(c, internal())
	}

	c.provider, c.factory = p, g.providers[name]

	return nil
}

// providerFailed audits a failed Provider call and returns the Gateway
// error the client gets. The Provider's own messages go to neither.
func (g *Gateway) providerFailed(c *dnsCall, err error) error {
	c.event.ProviderStatus = providerStatus(err)

	return g.fail(c, providerError(err))
}

// succeed audits an allowed call that changed records at the Provider.
// The change is made even if its event is lost,
// which is logged.
func (g *Gateway) succeed(c *dnsCall) {
	c.event.Result = audit.ResultOK

	_ = g.writeAudit(c.request, c.event)
}

// fail audits an allowed call that failed, with the category of err, and
// returns err. The call fails even if its event is lost.
func (g *Gateway) fail(c *dnsCall, err error) error {
	return g.failed(c.request, c.event, err)
}
