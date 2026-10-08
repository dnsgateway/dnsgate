// Package keys holds the Gateway's signing and encryption keys.
//
// The token codec reaches keys only through Source, so a KMS-backed
// implementation can replace the PEM files without changing callers:
// private key material never has to leave the Source.
package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
)

// ErrUnknownKey is returned when no key with the requested kid exists.
var ErrUnknownKey = errors.New("unknown key ID")

// Source signs with the Gateway's Ed25519 signing key and performs X25519
// key agreement with its encryption key. Keys are addressed by kid.
type Source interface {
	// SigningKeyID returns the kid of the key Sign uses.
	SigningKeyID() string
	// Sign returns the Ed25519 signature of payload under the current
	// signing key.
	Sign(ctx context.Context, payload []byte) ([]byte, error)
	// VerificationKey returns the Ed25519 public key with the given kid.
	VerificationKey(kid string) (ed25519.PublicKey, error)
	// EncryptionKey returns the kid and X25519 public key new tokens are
	// encrypted to.
	EncryptionKey() (string, *ecdh.PublicKey)
	// SharedSecret returns the X25519 shared secret between the private
	// encryption key with the given kid and peer.
	SharedSecret(ctx context.Context, kid string, peer *ecdh.PublicKey) ([]byte, error)
}
