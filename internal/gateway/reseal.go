package gateway

import (
	"errors"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// resealToken reseals the token in req under the current encryption key.
// The token authorizes its own Resealing: the resealed token has the same
// claims and signature, so it grants its holder nothing new.
func (g *Gateway) resealToken(r *request, req *dnsgatev1.ResealTokenRequest) (*dnsgatev1.Response, error) {
	resealed, err := g.codec.Reseal(r.ctx, req.GetToken())

	switch {
	case errors.Is(err, token.ErrInvalid):
		return nil, g.deny(r, audit.Event{Event: audit.EventTokenReseal}, unauthenticated("invalid service token"))
	case err != nil:
		g.log.Error("resealing token", "request_id", r.id, "error", err)

		return nil, internal()
	}

	// Like the token it replaces, a resealed token must be traceable.
	if err := g.writeAudit(r, audit.Event{
		Event:          audit.EventTokenReseal,
		ServiceAccount: resealed.Claims.Subject,
		TokenID:        resealed.Claims.ID,
		Provider:       resealed.Claims.Provider,
		OldKeyID:       resealed.OldKeyID,
		NewKeyID:       resealed.NewKeyID,
		Result:         audit.ResultOK,
	}); err != nil {
		return nil, internal()
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ResealToken{
		ResealToken: &dnsgatev1.ResealTokenResponse{Token: resealed.Token},
	}}, nil
}
