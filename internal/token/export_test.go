package token

import "context"

// InnerJWS returns the signed claims, the inner JWS, of the Service Token
// sealed.
func (c *Codec) InnerJWS(ctx context.Context, sealed string) ([]byte, error) {
	return c.decrypt(ctx, sealed, c.now())
}
