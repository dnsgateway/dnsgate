package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josecipher "github.com/go-jose/go-jose/v4/cipher"

	"github.com/dnsgateway/dnsgate/internal/keys"
)

// Type is the typ header of the outer JWE.
const Type = "dnsgate+jwe"

const (
	keyAlgorithm      = jose.ECDH_ES_A256KW
	contentEncryption = jose.A256GCM
	signatureAlg      = jose.EdDSA
	kekSize           = 32

	headerEPK = "epk"
	headerAlg = "alg"
	headerTyp = "typ"
)

// ErrInvalid is returned by Open for any token that does not open: a
// malformed, tampered or foreign token, an unknown kid, or failed claim
// checks. Errors never include the token or its contents.
var ErrInvalid = errors.New("invalid service token")

// Codec seals claims into Service Tokens and opens them again, using keys
// from a keys.Source.
type Codec struct {
	keys keys.Source
	now  func() time.Time
}

// Option configures a Codec.
type Option func(*Codec)

// WithClock sets the clock Open checks nbf and exp against.
func WithClock(now func() time.Time) Option {
	return func(c *Codec) { c.now = now }
}

// NewCodec returns a Codec that uses src for every key operation.
func NewCodec(src keys.Source, opts ...Option) *Codec {
	c := &Codec{keys: src, now: time.Now}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// wireClaims is the sealed form of Claims. Its credential field shadows the
// embedded, redacting one so the real value is sealed.
type wireClaims struct {
	Claims

	Credential wireCredential `json:"credential"`
}

type wireCredential struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Seal signs claims with the current signing key and encrypts the result to
// the current encryption key.
func (c *Codec) Seal(ctx context.Context, claims Claims) (string, error) {
	payload, err := json.Marshal(wireClaims{
		Claims:     claims,
		Credential: wireCredential{Type: claims.Credential.Type, Value: claims.Credential.Value.Reveal()},
	})
	if err != nil {
		return "", fmt.Errorf("encoding claims: %w", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: signatureAlg, Key: &opaqueSigner{ctx: ctx, keys: c.keys}}, nil)
	if err != nil {
		return "", fmt.Errorf("creating signer: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing claims: %w", err)
	}

	signed, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serializing JWS: %w", err)
	}

	return c.encrypt([]byte(signed))
}

// encrypt produces a compact ECDH-ES+A256KW / A256GCM JWE over X25519.
// go-jose v4 has no X25519 key agreement, so the ephemeral agreement and
// key derivation (RFC 7518 section 4.6, RFC 8037) happen here and go-jose
// wraps the content key under the derived key (A256KW) and encrypts the
// content. The alg header is then set to ECDH-ES+A256KW with the epk, as the
// standard requires; go-jose applies extra headers last, and they are
// covered by the AES-GCM additional data.
func (c *Codec) encrypt(plaintext []byte) (string, error) {
	kid, recipient := c.keys.EncryptionKey()

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generating ephemeral key: %w", err)
	}

	z, err := eph.ECDH(recipient)
	if err != nil {
		return "", fmt.Errorf("key agreement: %w", err)
	}

	kek, err := deriveKEK(z)
	if err != nil {
		return "", err
	}

	opts := (&jose.EncrypterOptions{}).
		WithType(Type).
		WithHeader(headerAlg, keyAlgorithm).
		WithHeader(headerEPK, x25519JWK{
			Kty: "OKP",
			Crv: "X25519",
			X:   base64.RawURLEncoding.EncodeToString(eph.PublicKey().Bytes()),
		})

	enc, err := jose.NewEncrypter(contentEncryption, jose.Recipient{Algorithm: jose.A256KW, Key: kek, KeyID: kid}, opts)
	if err != nil {
		return "", fmt.Errorf("creating encrypter: %w", err)
	}

	jwe, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypting token: %w", err)
	}

	sealed, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serializing JWE: %w", err)
	}

	return sealed, nil
}

// Open decrypts and verifies a Service Token, choosing keys by kid, and
// checks its iss, aud, nbf and exp claims.
func (c *Codec) Open(ctx context.Context, sealed string) (Claims, error) {
	signed, err := c.decrypt(ctx, sealed)
	if err != nil {
		return Claims{}, err
	}

	jws, err := jose.ParseSignedCompact(string(signed), []jose.SignatureAlgorithm{signatureAlg})
	if err != nil || len(jws.Signatures) != 1 {
		return Claims{}, fmt.Errorf("%w: malformed signature", ErrInvalid)
	}

	pub, err := c.keys.VerificationKey(jws.Signatures[0].Header.KeyID)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	payload, err := jws.Verify(pub)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: bad signature", ErrInvalid)
	}

	var wire wireClaims

	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&wire); err != nil {
		return Claims{}, fmt.Errorf("%w: malformed claims", ErrInvalid)
	}

	claims := wire.Claims
	claims.Credential = Credential{Type: wire.Credential.Type, Value: NewSecret(wire.Credential.Value)}

	if err := c.check(claims); err != nil {
		return Claims{}, err
	}

	return claims, nil
}

func (c *Codec) decrypt(ctx context.Context, sealed string) ([]byte, error) {
	jwe, err := jose.ParseEncryptedCompact(sealed, []jose.KeyAlgorithm{keyAlgorithm}, []jose.ContentEncryption{contentEncryption})
	if err != nil {
		return nil, fmt.Errorf("%w: malformed", ErrInvalid)
	}

	if typ, _ := jwe.Header.ExtraHeaders[headerTyp].(string); typ != Type {
		return nil, fmt.Errorf("%w: typ is not %s", ErrInvalid, Type)
	}

	dk := &opaqueDecrypter{ctx: ctx, keys: c.keys}

	plaintext, err := jwe.Decrypt(dk)
	if err != nil {
		if dk.err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, dk.err)
		}

		return nil, fmt.Errorf("%w: decryption failed", ErrInvalid)
	}

	return plaintext, nil
}

func (c *Codec) check(claims Claims) error {
	now := c.now()

	switch {
	case claims.Issuer != Issuer:
		return fmt.Errorf("%w: wrong issuer", ErrInvalid)
	case claims.Audience != Audience:
		return fmt.Errorf("%w: wrong audience", ErrInvalid)
	case now.Before(claims.NotBefore.Time()):
		return fmt.Errorf("%w: not valid yet", ErrInvalid)
	case claims.Expiry != nil && !now.Before(claims.Expiry.Time()):
		return fmt.Errorf("%w: expired", ErrInvalid)
	}

	return nil
}

type x25519JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// opaqueSigner signs through keys.Source so private keys stay inside it.
type opaqueSigner struct {
	ctx  context.Context //nolint:containedctx // go-jose's signer interface carries no context
	keys keys.Source
}

func (s *opaqueSigner) Public() *jose.JSONWebKey {
	kid := s.keys.SigningKeyID()

	pub, err := s.keys.VerificationKey(kid)
	if err != nil {
		return nil
	}

	return &jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: string(signatureAlg)}
}

func (s *opaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{signatureAlg}
}

func (s *opaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != signatureAlg {
		return nil, jose.ErrUnsupportedAlgorithm
	}

	return s.keys.Sign(s.ctx, payload)
}

// opaqueDecrypter unwraps the content key through keys.Source. go-jose hides
// its errors, so the last key-lookup error is kept for Open to report.
type opaqueDecrypter struct {
	ctx  context.Context //nolint:containedctx // go-jose's decrypter interface carries no context
	keys keys.Source
	err  error
}

func (d *opaqueDecrypter) DecryptKey(encryptedKey []byte, header jose.Header) ([]byte, error) {
	if header.Algorithm != string(keyAlgorithm) {
		return nil, jose.ErrUnsupportedAlgorithm
	}

	peer, err := parseEPK(header.ExtraHeaders[headerEPK])
	if err != nil {
		return nil, err
	}

	z, err := d.keys.SharedSecret(d.ctx, header.KeyID, peer)
	if err != nil {
		d.err = err

		return nil, err
	}

	kek, err := deriveKEK(z)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	return josecipher.KeyUnwrap(block, encryptedKey)
}

func parseEPK(raw any) (*ecdh.PublicKey, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("missing epk")
	}

	x, _ := m["x"].(string)

	if m["kty"] != "OKP" || m["crv"] != "X25519" || len(m) != 3 {
		return nil, errors.New("epk is not an X25519 key")
	}

	b, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, errors.New("malformed epk")
	}

	return ecdh.X25519().NewPublicKey(b)
}

// deriveKEK runs the Concat KDF of RFC 7518 section 4.6.2 for
// ECDH-ES+A256KW with empty apu and apv.
func deriveKEK(z []byte) ([]byte, error) {
	var supPubInfo [4]byte

	binary.BigEndian.PutUint32(supPubInfo[:], kekSize*8)

	kdf := josecipher.NewConcatKDF(crypto.SHA256, z,
		lengthPrefixed([]byte(keyAlgorithm)), lengthPrefixed(nil), lengthPrefixed(nil),
		supPubInfo[:], nil)

	kek := make([]byte, kekSize)
	if _, err := io.ReadFull(kdf, kek); err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}

	return kek, nil
}

func lengthPrefixed(data []byte) []byte {
	out := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(out, uint32(len(data))) //nolint:gosec // inputs are short constants

	return append(out, data...)
}
