package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/revocation"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// revokeToken revokes the token req names, and with it every token
// derived from it. The presented token needs delete on tokens, and may
// then revoke any token ID: there is no registry to tell which chain an
// ID belongs to (ADR 0001).
func (g *Gateway) revokeToken(r *request, req *dnsgatev1.RevokeTokenRequest) (*dnsgatev1.Response, error) {
	event := audit.Event{Event: audit.EventTokenRevoke, Verb: string(permission.VerbDelete)}

	claims, err := g.openToken(r, event, req.GetToken())
	if err != nil {
		return nil, err
	}

	event.ServiceAccount, event.TokenID, event.Provider = claims.Subject, claims.ID, claims.Provider

	if !permission.Allows(claims.Permissions, permission.Request{Verb: permission.VerbDelete, Resource: permission.ResourceTokens}) {
		return nil, g.deny(r, event, permissionDenied("the token's permissions do not allow revoking tokens"))
	}

	// Only a token that may revoke gets its target parsed, or opened: a
	// denied caller learns nothing of it, and its event names none.
	entry, err := g.revocationTarget(r, req)
	if err != nil {
		return nil, g.deny(r, event, err)
	}

	event.RevokedTokenID = entry.ID

	if err := g.revocations.Revoke(r.ctx, entry); err != nil {
		g.log.Error("revoking token", "request_id", r.id, "error", err)

		return nil, g.failed(r, event, internal())
	}

	// Revoking only takes access away, so a lost event does not undo it.
	event.Result = audit.ResultOK
	_ = g.writeAudit(r, event)

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_RevokeToken{
		RevokeToken: &dnsgatev1.RevokeTokenResponse{Jti: entry.ID},
	}}, nil
}

// revocationTarget returns the entry to revoke the token req names: its
// ID, kept until the token's own expiry if req gives the token, or
// forever if req gives only an ID, or a token that never expires. A
// target that is malformed, or a token that does not open, is an error.
func (g *Gateway) revocationTarget(r *request, req *dnsgatev1.RevokeTokenRequest) (revocation.Entry, error) {
	switch target := req.GetTarget().(type) {
	case *dnsgatev1.RevokeTokenRequest_TokenId:
		if !token.ValidID(target.TokenId) {
			return revocation.Entry{}, invalidRequest("token_id is not a token ID")
		}

		return revocation.Entry{ID: target.TokenId}, nil
	case *dnsgatev1.RevokeTokenRequest_TargetToken:
		claims, err := g.codec.Open(r.ctx, target.TargetToken)
		if err != nil {
			return revocation.Entry{}, invalidRequest("the token to revoke does not open; revoke it by its ID")
		}

		entry := revocation.Entry{ID: claims.ID}
		if claims.Expiry != nil {
			entry.ExpiresAt = claims.Expiry.Time()
		}

		return entry, nil
	default:
		return revocation.Entry{}, invalidRequest("missing token_id or target_token")
	}
}
