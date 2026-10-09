package gateway

import (
	"errors"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// resealToken reseals the token in req under the current encryption key.
// The token authorizes its own Resealing: the resealed token has the same
// claims and signature, so it grants its holder nothing new. A revoked
// token is not resealed.
func (g *Gateway) resealToken(r *request, req *dnsgatev1.ResealTokenRequest) (*dnsgatev1.Response, error) {
	claims, err := g.codec.Open(r.ctx, req.GetToken())

	switch {
	case errors.Is(err, token.ErrInvalid):
		return nil, g.deny(r, audit.Event{Event: audit.EventTokenReseal}, unauthenticated("invalid service token"))
	case err != nil:
		g.log.Error("opening token to reseal", "request_id", r.id, "error", err)

		return nil, internal()
	}

	event := audit.Event{
		Event:          audit.EventTokenReseal,
		ServiceAccount: claims.Subject,
		TokenID:        claims.ID,
		Provider:       claims.Provider,
	}

	// A revoked token stays revoked under any key, and is refused before
	// it is resealed.
	if err := g.checkRevoked(r, event, claims); err != nil {
		return nil, err
	}

	resealed, err := g.codec.Reseal(r.ctx, req.GetToken())

	switch {
	case errors.Is(err, token.ErrInvalid):
		return nil, g.deny(r, event, unauthenticated("invalid service token"))
	case err != nil:
		g.log.Error("resealing token", "request_id", r.id, "error", err)

		return nil, internal()
	}

	event.OldKeyID, event.NewKeyID = resealed.OldKeyID, resealed.NewKeyID

	// Like the token it replaces, a resealed token must be traceable.
	event.Result = audit.ResultOK

	if err := g.writeAudit(r, event); err != nil {
		return nil, internal()
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ResealToken{
		ResealToken: &dnsgatev1.ResealTokenResponse{Token: resealed.Token},
	}}, nil
}
