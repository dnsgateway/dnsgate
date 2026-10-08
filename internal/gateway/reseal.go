package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
)

// resealToken reseals the token in req under the current encryption key.
// The token authorizes its own Resealing: the resealed token has the same
// claims and signature, so it grants its holder nothing new.
func (g *Gateway) resealToken(r *request, req *dnsgatev1.ResealTokenRequest) (*dnsgatev1.Response, error) {
	resealed, claims, err := g.codec.Reseal(r.ctx, req.GetToken())
	if err != nil {
		return nil, g.deny(r, audit.EventTokenReseal, unauthenticated("invalid service token"))
	}

	// Like the token it replaces, a resealed token must be traceable.
	if err := g.writeAudit(r, audit.Event{
		Event:          audit.EventTokenReseal,
		ServiceAccount: claims.Subject,
		TokenID:        claims.ID,
		Provider:       claims.Provider,
		Result:         audit.ResultOK,
	}); err != nil {
		return nil, internal()
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ResealToken{
		ResealToken: &dnsgatev1.ResealTokenResponse{Token: resealed},
	}}, nil
}
