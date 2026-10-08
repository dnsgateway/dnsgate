package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const (
	signingPrefix    = "sig-"
	encryptionPrefix = "enc-"

	pemPrivateKey = "PRIVATE KEY"
	pemPublicKey  = "PUBLIC KEY"
	pemHeaderKID  = "kid"

	dirMode  = 0o700
	fileMode = 0o600
)

var validSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Generated describes the key pairs written by Generate.
type Generated struct {
	SigningKeyID    string
	EncryptionKeyID string
	// Files lists the written paths: signing private and public key, then
	// encryption private and public key.
	Files []string
}

// Generate writes a new Ed25519 signing key pair and X25519 encryption key
// pair into dir as PEM files with owner-only permissions. The kids are
// "sig-<suffix>" and "enc-<suffix>"; each file is named after its kid and
// carries it in a "kid" PEM header. dir is created with mode 0700 if it
// does not exist. Existing files are never overwritten.
func Generate(dir, suffix string) (Generated, error) {
	if !validSuffix.MatchString(suffix) {
		return Generated{}, fmt.Errorf("invalid key ID suffix %q: use letters, digits, '.', '_' and '-'", suffix)
	}

	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Generated{}, fmt.Errorf("generating signing key: %w", err)
	}

	encPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Generated{}, fmt.Errorf("generating encryption key: %w", err)
	}

	gen := Generated{
		SigningKeyID:    signingPrefix + suffix,
		EncryptionKeyID: encryptionPrefix + suffix,
	}

	type keyFile struct {
		path, kid, blockType string
		key                  any
	}

	files := []keyFile{
		{filepath.Join(dir, gen.SigningKeyID+".pem"), gen.SigningKeyID, pemPrivateKey, sigPriv},
		{filepath.Join(dir, gen.SigningKeyID+".pub.pem"), gen.SigningKeyID, pemPublicKey, sigPub},
		{filepath.Join(dir, gen.EncryptionKeyID+".pem"), gen.EncryptionKeyID, pemPrivateKey, encPriv},
		{filepath.Join(dir, gen.EncryptionKeyID+".pub.pem"), gen.EncryptionKeyID, pemPublicKey, encPriv.PublicKey()},
	}

	for _, f := range files {
		if _, err := os.Lstat(f.path); err == nil {
			return Generated{}, fmt.Errorf("key file %s already exists", f.path)
		}
	}

	if err := os.MkdirAll(dir, dirMode); err != nil {
		return Generated{}, fmt.Errorf("creating key directory: %w", err)
	}

	for _, f := range files {
		var der []byte

		if f.blockType == pemPrivateKey {
			der, err = x509.MarshalPKCS8PrivateKey(f.key)
		} else {
			der, err = x509.MarshalPKIXPublicKey(f.key)
		}

		if err != nil {
			return Generated{}, fmt.Errorf("encoding %s: %w", f.path, err)
		}

		block := &pem.Block{Type: f.blockType, Headers: map[string]string{pemHeaderKID: f.kid}, Bytes: der}

		if err := writeExclusive(f.path, pem.EncodeToMemory(block)); err != nil {
			return Generated{}, err
		}

		gen.Files = append(gen.Files, f.path)
	}

	return gen, nil
}

func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()

		return fmt.Errorf("writing key file %s: %w", path, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("writing key file %s: %w", path, err)
	}

	return nil
}

// Files is a Source backed by one signing and one encryption private key
// read from PEM files.
type Files struct {
	sigKID  string
	sigPriv ed25519.PrivateKey
	encKID  string
	encPriv *ecdh.PrivateKey
}

var _ Source = (*Files)(nil)

// LoadFiles reads the signing (Ed25519) and encryption (X25519) private
// keys written by Generate. Each file must carry a "kid" PEM header and
// must not be readable or writable by group or others.
func LoadFiles(signingFile, encryptionFile string) (*Files, error) {
	sigKID, sigKey, err := readPrivateKey(signingFile)
	if err != nil {
		return nil, err
	}

	sigPriv, ok := sigKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s is not an Ed25519 private key", signingFile)
	}

	encKID, encKey, err := readPrivateKey(encryptionFile)
	if err != nil {
		return nil, err
	}

	encPriv, ok := encKey.(*ecdh.PrivateKey)
	if !ok || encPriv.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("encryption key %s is not an X25519 private key", encryptionFile)
	}

	return &Files{sigKID: sigKID, sigPriv: sigPriv, encKID: encKID, encPriv: encPriv}, nil
}

func readPrivateKey(path string) (string, any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", nil, fmt.Errorf("reading key file: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", nil, fmt.Errorf("key file %s has mode %o, want no group or other access (600)", path, perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPrivateKey {
		return "", nil, fmt.Errorf("key file %s holds no PEM %q block", path, pemPrivateKey)
	}

	kid := block.Headers[pemHeaderKID]
	if kid == "" {
		return "", nil, fmt.Errorf("key file %s has no %q PEM header", path, pemHeaderKID)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("parsing key file %s: %w", path, err)
	}

	return kid, key, nil
}

// SigningKeyID implements Source.
func (f *Files) SigningKeyID() string { return f.sigKID }

// Sign implements Source.
func (f *Files) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(f.sigPriv, payload), nil
}

// VerificationKey implements Source.
func (f *Files) VerificationKey(kid string) (ed25519.PublicKey, error) {
	if kid != f.sigKID {
		return nil, fmt.Errorf("signing key %q: %w", kid, ErrUnknownKey)
	}

	pub, ok := f.sigPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing key has no Ed25519 public key")
	}

	return pub, nil
}

// EncryptionKey implements Source.
func (f *Files) EncryptionKey() (string, *ecdh.PublicKey) {
	return f.encKID, f.encPriv.PublicKey()
}

// SharedSecret implements Source.
func (f *Files) SharedSecret(_ context.Context, kid string, peer *ecdh.PublicKey) ([]byte, error) {
	if kid != f.encKID {
		return nil, fmt.Errorf("encryption key %q: %w", kid, ErrUnknownKey)
	}

	secret, err := f.encPriv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("key agreement: %w", err)
	}

	return secret, nil
}
