package gateway

import (
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// revokeToken revokes the token req names, and with it every token
// derived from it. The presented token needs delete on tokens, and may
// then revoke any token ID: there is no registry to tell which chain an
// ID belongs to (ADR 0001).
func (g *Gateway) revokeToken(r *request, req *dnsgatev1.RevokeTokenRequest) (*dnsgatev1.Response, error) {
	event := audit.Event{Event: audit.EventTokenRevoke, Verb: string(permission.VerbDelete)}

	// Like a record request's zone, a well-formed target names the event
	// from the start, so even a denial records what it would revoke.
	id, expiresAt, targetErr := g.revocationTarget(r, req)
	event.RevokedTokenID = id

	claims, err := g.openToken(r, event, req.GetToken())
	if err != nil {
		return nil, err
	}

	event.ServiceAccount, event.TokenID, event.Provider = claims.Subject, claims.ID, claims.Provider

	if !permission.Allows(claims.Permissions, permission.Request{Verb: permission.VerbDelete, Resource: permission.ResourceTokens}) {
		return nil, g.deny(r, event, permissionDenied("the token's permissions do not allow revoking tokens"))
	}

	if targetErr != nil {
		return nil, g.deny(r, event, targetErr)
	}

	if err := g.revocations.Revoke(r.ctx, id, expiresAt); err != nil {
		g.log.Error("revoking token", "request_id", r.id, "error", err)

		event.Result, event.Category = audit.ResultFailed, category(internal())
		_ = g.writeAudit(r, event)

		return nil, internal()
	}

	// Revoking only takes access away, so a lost event does not undo it.
	event.Result = audit.ResultOK
	_ = g.writeAudit(r, event)

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_RevokeToken{
		RevokeToken: &dnsgatev1.RevokeTokenResponse{Jti: id},
	}}, nil
}

// revocationTarget returns the ID of the token req names and the expiry
// to keep its revocation until: the token's own, if req gives the token,
// or the zero time, forever, if req gives only an ID, or a token that
// never expires. A target that is malformed, or a token that does not
// open, is an error, and its ID is left empty.
func (g *Gateway) revocationTarget(r *request, req *dnsgatev1.RevokeTokenRequest) (string, time.Time, error) {
	switch target := req.GetTarget().(type) {
	case *dnsgatev1.RevokeTokenRequest_TokenId:
		if !validTokenID(target.TokenId) {
			return "", time.Time{}, invalidRequest("token_id is not a token ID")
		}

		return target.TokenId, time.Time{}, nil
	case *dnsgatev1.RevokeTokenRequest_TargetToken:
		claims, err := g.codec.Open(r.ctx, target.TargetToken)
		if err != nil {
			return "", time.Time{}, invalidRequest("the token to revoke does not open; revoke it by its ID")
		}

		if claims.Expiry == nil {
			return claims.ID, time.Time{}, nil
		}

		return claims.ID, claims.Expiry.Time(), nil
	default:
		return "", time.Time{}, invalidRequest("missing token_id or target_token")
	}
}

// validTokenID reports whether id has the form of the token IDs the
// Gateway issues: "tok_" and a ULID.
func validTokenID(id string) bool {
	rest, ok := strings.CutPrefix(id, tokenIDPrefix)
	if !ok {
		return false
	}

	_, err := ulid.ParseStrict(rest)

	return err == nil
}
