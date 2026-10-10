package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"

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

	if len(parent.Ancestors) >= g.maxAncestors {
		return nil, g.deny(r, event, permissionDenied("the token chain is at its maximum depth"))
	}

	if err := checkCreateTokenRequest(req); err != nil {
		return nil, g.deny(r, event, err)
	}

	now := g.now()

	derived := token.Claims{
		Subject:     req.GetSub(),
		ID:          g.newID(token.IDPrefix),
		IssuedAt:    token.NewNumericDate(now),
		NotBefore:   token.NewNumericDate(now),
		Ancestors:   append(append([]string{}, parent.Ancestors...), parent.ID),
		Provider:    parent.Provider,
		Credential:  parent.Credential,
		Permissions: permission.FromAPI(req.GetPermissions()),
	}

	if req.Expires != nil {
		exp := token.NewNumericDate(now.Add(req.GetExpires().AsDuration()))
		derived.Expiry = &exp
	}

	if dim, ok := narrows(parent, derived); !ok {
		return nil, g.deny(r, event, narrowingViolation(dim))
	}

	sealed, err := g.codec.Seal(r.ctx, derived)
	if err != nil {
		g.log.Error("sealing derived token", "request_id", r.id, "error", err)

		return nil, internal()
	}

	// A Derived Token whose token.create event is lost would be
	// untraceable.
	event.ServiceAccount, event.TokenID, event.Result = derived.Subject, derived.ID, audit.ResultOK

	if err := g.writeAudit(r, event); err != nil {
		return nil, internal()
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_CreateToken{
		CreateToken: &dnsgatev1.CreateTokenResponse{Token: sealed, Jti: derived.ID},
	}}, nil
}

// checkCreateTokenRequest checks that req names a Service Account and
// well-formed Permissions, each with verbs, and a positive expiry.
func checkCreateTokenRequest(req *dnsgatev1.CreateTokenRequest) error {
	switch {
	case req.GetSub() == "":
		return invalidRequest("missing sub")
	case len(req.GetPermissions()) == 0:
		return invalidRequest("missing permissions")
	case req.Expires != nil && req.GetExpires().AsDuration() <= 0:
		return invalidRequest("expires must be positive")
	}

	if err := permission.Check(permission.FromAPI(req.GetPermissions())); err != nil {
		return invalidRequest(err.Error())
	}

	return nil
}

// narrows reports whether derived stays within parent (Narrowing), and if
// not, the dimension where it exceeds parent: its expiry, which must be
// no later than the parent's, or its Permissions, which the parent's
// must cover.
func narrows(parent, derived token.Claims) (permission.Dimension, bool) {
	if parent.Expiry != nil && (derived.Expiry == nil || *derived.Expiry > *parent.Expiry) {
		return permission.DimensionExp, false
	}

	return permission.Covers(parent.Permissions, derived.Permissions)
}
