package gateway

import (
	"time"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// dnsCall is a zone or record request on its way to the Provider. Its
// audit event fills in as the request passes each check, in the
// documented order: open the token (decrypt, verify, check iss, aud, nbf
// and exp), check its Permissions, check the Egress, and only then build
// the Provider from the Provider Credential.
type dnsCall struct {
	*request

	event audit.Event
	start time.Time
}

func newDNSCall(r *request, event audit.Name, verb string) *dnsCall {
	return &dnsCall{
		request: r,
		event:   audit.Event{Event: event, Verb: verb},
		start:   time.Now(),
	}
}

// egressNames maps the Egress a request asks for to its Permission name;
// empty when the request leaves the choice to the Gateway.
var egressNames = map[dnsgatev1.Egress]string{
	dnsgatev1.Egress_EGRESS_UNSPECIFIED: "",
	dnsgatev1.Egress_EGRESS_GATEWAY:     permission.EgressGateway,
	dnsgatev1.Egress_EGRESS_AGENT:       permission.EgressAgent,
}

// openToken opens the Service Token tok and names its holder in the
// call's audit event.
func (g *Gateway) openToken(c *dnsCall, tok string) (token.Claims, error) {
	claims, err := g.codec.Open(c.ctx, tok)
	if err != nil {
		return token.Claims{}, g.refuse(c, audit.ResultDenied, unauthenticated("invalid service token"))
	}

	c.event.ServiceAccount = claims.Subject
	c.event.TokenID = claims.ID
	c.event.Provider = claims.Provider

	return claims, nil
}

// authorize checks that the Egress is supported and that the token's
// Permissions allow pr through the requested Egress, or through the
// Egress chosen for it. Agent Egress is not supported yet: a request for
// it is refused whatever the token allows, and so is a token that allows
// only Agent Egress, which never falls back to Gateway Egress. authorize
// returns the Egress.
func (g *Gateway) authorize(c *dnsCall, claims token.Claims, requested dnsgatev1.Egress, pr permission.Request) (string, error) {
	name, ok := egressNames[requested]
	if !ok {
		return "", g.refuse(c, audit.ResultDenied, invalidRequest("unknown egress"))
	}

	c.event.RequestedEgress = name
	if name == permission.EgressAgent {
		return "", g.refuse(c, audit.ResultDenied, agentEgressNotSupported())
	}

	pr.Egress = name

	egress, ok := permission.ChooseEgress(claims.Permissions, pr)
	if !ok {
		return "", g.refuse(c, audit.ResultDenied, permissionDenied("the token's permissions do not allow the request"))
	}

	if egress != permission.EgressGateway {
		return "", g.refuse(c, audit.ResultDenied, agentEgressNotSupported())
	}

	c.event.Egress = egress

	return egress, nil
}

// connect builds the token's Provider from its Provider Credential. The
// plaintext credential lives on only inside the Provider, which the
// caller drops when its request is done.
func (g *Gateway) connect(c *dnsCall, claims token.Claims) (dnsprovider.Provider, error) {
	p, err := g.providers.New(claims.Provider, provider.CredentialFields(claims.Provider, claims.Credential.Value.Reveal()))
	if err != nil {
		g.log.Error("building provider", "request_id", c.id, "provider", claims.Provider, "error", err)

		return nil, g.refuse(c, audit.ResultFailed, internal())
	}

	return p, nil
}

// providerFailed audits a failed Provider call and returns the Gateway
// error the client gets. The Provider's own messages go to the audit
// event alone.
func (g *Gateway) providerFailed(c *dnsCall, err error) error {
	c.event.ProviderStatus = providerStatus(err)
	c.event.ProviderMessages = providerMessages(err)

	return g.refuse(c, audit.ResultFailed, providerError(err))
}

// refuse audits the call as result with the category of err, and returns
// err. The request is refused even if its event is lost.
func (g *Gateway) refuse(c *dnsCall, result audit.Result, err error) error {
	c.event.Result = result
	c.event.Category = category(err)

	if c.event.Egress != "" {
		c.event.DurationMS = time.Since(c.start).Milliseconds()
	}

	_ = g.writeAudit(c.request, c.event)

	return err
}
