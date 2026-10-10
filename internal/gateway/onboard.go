package gateway

import (
	"crypto/subtle"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"

	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// rootServiceAccount is the sub of every Root Token.
const rootServiceAccount = "root"

// rootPermissions are the full Permissions of a Root Token.
func rootPermissions() []token.Permission {
	return []token.Permission{{
		Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
		Resources: []string{"zones", "records", "tokens"},
		Zones:     []string{"*"},
		Names:     []string{"@", "**"},
		Types:     []string{"*"},
		Egress:    []string{"gateway", "agent"},
	}}
}

// onboard turns the Provider Credential in req into a Root Token. The
// plaintext credential lives only in req and the claims being sealed.
func (g *Gateway) onboard(r *request, req *dnsgatev1.OnboardRequest) (*dnsgatev1.Response, error) {
	if !g.checkBootstrapSecret(req.GetBootstrapSecret()) {
		return nil, g.deny(r, audit.Event{Event: audit.EventOnboard}, unauthenticated("wrong or missing bootstrap secret"))
	}

	if err := checkOnboardRequest(req); err != nil {
		return nil, g.deny(r, audit.Event{Event: audit.EventOnboard}, err)
	}

	now := g.now()

	claims := token.Claims{
		Subject:   rootServiceAccount,
		ID:        g.newID(token.IDPrefix),
		IssuedAt:  token.NewNumericDate(now),
		NotBefore: token.NewNumericDate(now),
		Provider:  req.GetProvider(),
		Credential: token.Credential{
			Type:  req.GetCredential().GetType(),
			Value: token.NewSecret(req.GetCredential().GetValue()),
		},
		Permissions: rootPermissions(),
	}

	if req.Expires != nil {
		exp := token.NewNumericDate(now.Add(req.GetExpires().AsDuration()))
		claims.Expiry = &exp
	}

	sealed, err := g.codec.Seal(r.ctx, claims)
	if err != nil {
		g.log.Error("sealing root token", "request_id", r.id, "error", err)

		return nil, internal()
	}

	// A Root Token whose onboard event is lost would be untraceable.
	if err := g.writeAudit(r, audit.Event{
		Event:          audit.EventOnboard,
		ServiceAccount: claims.Subject,
		TokenID:        claims.ID,
		Provider:       claims.Provider,
		Result:         audit.ResultOK,
	}); err != nil {
		return nil, internal()
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_Onboard{
		Onboard: &dnsgatev1.OnboardResponse{Token: sealed},
	}}, nil
}

// checkOnboardRequest checks that req names a supported Provider and
// credential type and a usable expiry.
func checkOnboardRequest(req *dnsgatev1.OnboardRequest) error {
	credType, ok := provider.CredentialType(req.GetProvider())

	switch {
	case !ok:
		return invalidRequest("unsupported provider")
	case req.GetCredential().GetType() != credType:
		return invalidRequest("unsupported credential type for the provider")
	case req.GetCredential().GetValue() == "":
		return invalidRequest("missing credential")
	case req.Expires != nil && req.GetExpires().AsDuration() < time.Second:
		return invalidRequest("expires must be at least one second")
	}

	return nil
}

// checkBootstrapSecret reports whether got is the configured bootstrap
// secret, in constant time.
func (g *Gateway) checkBootstrapSecret(got string) bool {
	want := g.bootstrap.Reveal()

	return want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
