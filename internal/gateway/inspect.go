package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// inspectToken opens the token in req and returns its claims, without the
// Provider Credential.
func (g *Gateway) inspectToken(r *request, req *dnsgatev1.InspectTokenRequest) (*dnsgatev1.Response, error) {
	claims, err := g.openToken(r, audit.Event{Event: audit.EventTokenInspect}, req.GetToken())
	if err != nil {
		return nil, err
	}

	out := &dnsgatev1.InspectTokenResponse{
		Sub:         claims.Subject,
		Jti:         claims.ID,
		Ancestors:   claims.Ancestors,
		Iat:         timestamp(claims.IssuedAt),
		Nbf:         timestamp(claims.NotBefore),
		Provider:    claims.Provider,
		Permissions: make([]*dnsgatev1.Permission, 0, len(claims.Permissions)),
	}

	if claims.Expiry != nil {
		out.Exp = timestamp(*claims.Expiry)
	}

	for _, p := range claims.Permissions {
		out.Permissions = append(out.Permissions, permissionToAPI(p))
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_InspectToken{InspectToken: out}}, nil
}

// permissionsFromAPI returns the API's Permissions as a token's.
func permissionsFromAPI(perms []*dnsgatev1.Permission) []token.Permission {
	out := make([]token.Permission, 0, len(perms))

	for _, p := range perms {
		out = append(out, token.Permission{
			Verbs:     p.GetVerbs(),
			Resources: p.GetResources(),
			Zones:     p.GetZones(),
			Names:     p.GetNames(),
			Types:     p.GetTypes(),
			Egress:    p.GetEgress(),
		})
	}

	return out
}

// permissionToAPI returns a token's Permission as the API's.
func permissionToAPI(p token.Permission) *dnsgatev1.Permission {
	return &dnsgatev1.Permission{
		Verbs:     p.Verbs,
		Resources: p.Resources,
		Zones:     p.Zones,
		Names:     p.Names,
		Types:     p.Types,
		Egress:    p.Egress,
	}
}
