package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// createToken issues a Derived Token of the Parent Token in req. The
// Derived Token copies the parent's Provider and Provider Credential,
// which never leave the Gateway.
func (g *Gateway) createToken(r *request, req *dnsgatev1.CreateTokenRequest) (*dnsgatev1.Response, error) {
	event := audit.Event{Event: audit.EventTokenCreate, Verb: string(permission.VerbCreate)}

	parent, err := g.openToken(r, event, req.GetToken())
	if err != nil {
		return nil, err
	}

	event.ParentTokenID, event.Provider = parent.ID, parent.Provider

	if !permission.Allows(parent.Permissions, permission.Request{Verb: permission.VerbCreate, Resource: permission.ResourceTokens}) {
		return nil, g.deny(r, event, permissionDenied("the token's permissions do not allow issuing tokens"))
	}

	now := g.now()

	child := token.Claims{
		Subject:     req.GetSub(),
		ID:          g.newID(tokenIDPrefix),
		IssuedAt:    token.NewNumericDate(now),
		NotBefore:   token.NewNumericDate(now),
		Ancestors:   append(append([]string{}, parent.Ancestors...), parent.ID),
		Provider:    parent.Provider,
		Credential:  parent.Credential,
		Permissions: permissionsFromAPI(req.GetPermissions()),
	}

	sealed, err := g.codec.Seal(r.ctx, child)
	if err != nil {
		g.log.Error("sealing derived token", "request_id", r.id, "error", err)

		return nil, internal()
	}

	// A Derived Token whose token.create event is lost would be
	// untraceable.
	event.ServiceAccount, event.TokenID, event.Result = child.Subject, child.ID, audit.ResultOK

	if err := g.writeAudit(r, event); err != nil {
		return nil, internal()
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_CreateToken{
		CreateToken: &dnsgatev1.CreateTokenResponse{Token: sealed, Jti: child.ID},
	}}, nil
}

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
