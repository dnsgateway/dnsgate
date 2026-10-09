package token

import "context"

// InnerJWS returns the signed claims, the inner JWS, of the Service Token
// sealed.
func (c *Codec) InnerJWS(ctx context.Context, sealed string) ([]byte, error) {
	plaintext, _, err := c.decrypt(ctx, sealed, c.now())

	return plaintext, err
}

// SealAs seals claims like Seal, with iss and aud as given, for tokens the
// Gateway never mints.
func (c *Codec) SealAs(ctx context.Context, claims Claims, iss, aud string) (string, error) {
	return c.seal(ctx, wireClaims{
		Claims:     claims,
		Issuer:     iss,
		Audience:   aud,
		Credential: wireCredential{Type: claims.Credential.Type, Value: claims.Credential.Value.Reveal()},
	})
}
