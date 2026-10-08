package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// inspectToken opens the token in req and returns its claims, without the
// Provider Credential.
func (g *Gateway) inspectToken(r *request, req *dnsgatev1.InspectTokenRequest) (*dnsgatev1.Response, error) {
	claims, err := g.codec.Open(r.ctx, req.GetToken())
	if err != nil {
		return nil, g.deny(r, audit.EventTokenInspect, unauthenticated("invalid service token"))
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
