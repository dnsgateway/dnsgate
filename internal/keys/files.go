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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	signingPrefix    = "sig-"
	encryptionPrefix = "enc-"

	pemPrivateKey = "PRIVATE KEY"
	pemPublicKey  = "PUBLIC KEY"
	privateExt    = ".pem"
	publicExt     = ".pub.pem"

	dirMode  = 0o700
	fileMode = 0o600
)

// KeyIDFormat describes the kids Generate writes and LoadFiles accepts. It
// is the one description of the format; help texts refer to it.
const KeyIDFormat = signingPrefix + "<suffix> for the signing key and " +
	encryptionPrefix + "<suffix> for the encryption key, where <suffix> starts " +
	"with a letter or digit, followed by letters, digits, '.', '_' or '-'"

var validSuffix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// checkKeyID reports whether kid is prefix followed by a valid suffix.
func checkKeyID(kid, prefix string) error {
	if suffix, ok := strings.CutPrefix(kid, prefix); !ok || !validSuffix.MatchString(suffix) {
		return fmt.Errorf("invalid key ID %q: want %s", kid, KeyIDFormat)
	}

	return nil
}

// Generated describes the key pairs written by Generate.
type Generated struct {
	SigningKeyID    string
	EncryptionKeyID string
	// Files lists the written paths: signing private and public key, then
	// encryption private and public key.
	Files []string
}

// Generate writes a new Ed25519 signing key pair and X25519 encryption key
// pair into dir as PEM files with owner-only permissions. The kids follow
// KeyIDFormat, and each file is named after its kid:
// <kid>.pem holds the PKCS #8 private key, <kid>.pub.pem the PKIX public
// key. dir is created with mode 0700 if it does not exist; an existing dir
// must give group and others no access. Existing files are never
// overwritten, and on failure the files this call wrote are removed.
func Generate(dir, suffix string) (Generated, error) {
	if !validSuffix.MatchString(suffix) {
		return Generated{}, fmt.Errorf("invalid key ID suffix %q: want %s", suffix, KeyIDFormat)
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
		path   string
		key    any
		encode func(key any) ([]byte, error)
	}

	files := []keyFile{
		{filepath.Join(dir, gen.SigningKeyID+privateExt), sigPriv, encodePrivate},
		{filepath.Join(dir, gen.SigningKeyID+publicExt), sigPub, encodePublic},
		{filepath.Join(dir, gen.EncryptionKeyID+privateExt), encPriv, encodePrivate},
		{filepath.Join(dir, gen.EncryptionKeyID+publicExt), encPriv.PublicKey(), encodePublic},
	}

	if err := prepareDir(dir); err != nil {
		return Generated{}, err
	}

	for _, f := range files {
		data, err := f.encode(f.key)
		if err == nil {
			err = writeExclusive(f.path, data)
		}

		if err != nil {
			// Leave no partial key set behind: remove what this call wrote.
			for _, path := range gen.Files {
				_ = os.Remove(path)
			}

			return Generated{}, fmt.Errorf("writing %s: %w", f.path, err)
		}

		gen.Files = append(gen.Files, f.path)
	}

	return gen, nil
}

// encodePrivate encodes key as a PEM PKCS #8 private key.
func encodePrivate(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: der}), nil
}

// encodePublic encodes key as a PEM PKIX public key.
func encodePublic(key any) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemPublicKey, Bytes: der}), nil
}

// prepareDir creates dir with mode 0700, or checks that an existing dir
// gives group and others no access.
func prepareDir(dir string) error {
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("creating key directory: %w", err)
		}

		return nil
	}

	if err != nil {
		return fmt.Errorf("checking key directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("key directory %s is not a directory", dir)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("key directory %s has mode %o, want no group or other access (700)", dir, perm)
	}

	return nil
}

// writeExclusive creates path, failing if it exists, and writes data to
// it. A file it created but could not fill is removed.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}

	_, err = f.Write(data)

	if closeErr := f.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		_ = os.Remove(path)

		return err
	}

	return nil
}

// Files is a Source backed by PEM files: one signing key, the current
// encryption key, and any older encryption keys kept as decryption keys
// until their retirement deadlines.
type Files struct {
	sig namedKey[ed25519.PrivateKey]
	enc namedKey[*ecdh.PrivateKey]
	// decryption holds the older encryption keys by kid.
	decryption map[string]decryptionKey
}

// namedKey is a private key and its kid.
type namedKey[K any] struct {
	kid string
	key K
}

// decryptionKey is an older encryption key and the time from which it no
// longer opens tokens.
type decryptionKey struct {
	key      *ecdh.PrivateKey
	retireAt time.Time
}

var _ Source = (*Files)(nil)

// Option configures LoadFiles.
type Option func(*loadOptions)

type loadOptions struct {
	decryption []decryptionKeyFile
}

type decryptionKeyFile struct {
	path     string
	retireAt time.Time
}

// WithDecryptionKey adds the older encryption key in path, written by
// Generate, as a decryption key: tokens sealed under it still open until
// retireAt, and none open from then on. New tokens are never sealed under
// it.
func WithDecryptionKey(path string, retireAt time.Time) Option {
	return func(o *loadOptions) {
		o.decryption = append(o.decryption, decryptionKeyFile{path: path, retireAt: retireAt})
	}
}

// LoadFiles reads the signing (Ed25519) and encryption (X25519) private
// keys written by Generate, and the decryption keys given as options. A
// key's kid is its file name without ".pem" and must follow KeyIDFormat,
// every encryption kid must be distinct, and no file may be readable or
// writable by group or others.
func LoadFiles(signingFile, encryptionFile string, opts ...Option) (*Files, error) {
	var o loadOptions

	for _, opt := range opts {
		opt(&o)
	}

	sig, err := readPrivateKey[ed25519.PrivateKey](signingFile, signingPrefix, "Ed25519")
	if err != nil {
		return nil, err
	}

	enc, err := readEncryptionKey(encryptionFile)
	if err != nil {
		return nil, err
	}

	f := &Files{sig: sig, enc: enc, decryption: make(map[string]decryptionKey, len(o.decryption))}

	for _, d := range o.decryption {
		k, err := readEncryptionKey(d.path)
		if err != nil {
			return nil, err
		}

		if _, dup := f.decryption[k.kid]; dup || k.kid == enc.kid {
			return nil, fmt.Errorf("key file %s: encryption key ID %q is used twice", d.path, k.kid)
		}

		f.decryption[k.kid] = decryptionKey{key: k.key, retireAt: d.retireAt}
	}

	return f, nil
}

// readEncryptionKey reads the X25519 private key in path.
func readEncryptionKey(path string) (namedKey[*ecdh.PrivateKey], error) {
	k, err := readPrivateKey[*ecdh.PrivateKey](path, encryptionPrefix, "X25519")
	if err != nil {
		return k, err
	}

	if k.key.Curve() != ecdh.X25519() {
		return namedKey[*ecdh.PrivateKey]{}, fmt.Errorf("key file %s is not an X25519 private key", path)
	}

	return k, nil
}

// readPrivateKey reads the private key in path, checking that its kid is
// prefix plus a valid suffix and that the key is a K (an algo key).
func readPrivateKey[K any](path, prefix, algo string) (namedKey[K], error) {
	kid, ok := strings.CutSuffix(filepath.Base(path), privateExt)
	if !ok {
		return namedKey[K]{}, fmt.Errorf("key file %s is not named <kid>%s", path, privateExt)
	}

	if err := checkKeyID(kid, prefix); err != nil {
		return namedKey[K]{}, fmt.Errorf("key file %s: %w", path, err)
	}

	// Check the mode of the file actually read: stat and read one descriptor.
	f, err := os.Open(path)
	if err != nil {
		return namedKey[K]{}, fmt.Errorf("reading key file: %w", err)
	}

	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return namedKey[K]{}, fmt.Errorf("reading key file: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return namedKey[K]{}, fmt.Errorf("key file %s has mode %o, want no group or other access (600)", path, perm)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return namedKey[K]{}, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPrivateKey {
		return namedKey[K]{}, fmt.Errorf("key file %s holds no PEM %q block", path, pemPrivateKey)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return namedKey[K]{}, fmt.Errorf("parsing key file %s: %w", path, err)
	}

	k, ok := key.(K)
	if !ok {
		return namedKey[K]{}, fmt.Errorf("key file %s is not an %s private key", path, algo)
	}

	return namedKey[K]{kid: kid, key: k}, nil
}

// SigningKeyID implements Source.
func (f *Files) SigningKeyID() string { return f.sig.kid }

// Sign implements Source.
func (f *Files) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(f.sig.key, payload), nil
}

// VerificationKey implements Source.
func (f *Files) VerificationKey(kid string) (ed25519.PublicKey, error) {
	if kid != f.sig.kid {
		return nil, fmt.Errorf("signing key %q: %w", kid, ErrUnknownKey)
	}

	pub, ok := f.sig.key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signing key has no Ed25519 public key")
	}

	return pub, nil
}

// EncryptionKey implements Source.
func (f *Files) EncryptionKey() (string, *ecdh.PublicKey) {
	return f.enc.kid, f.enc.key.PublicKey()
}

// SharedSecret implements Source. It agrees under the current encryption
// key or under a decryption key before its retirement deadline.
func (f *Files) SharedSecret(_ context.Context, kid string, peer *ecdh.PublicKey, at time.Time) ([]byte, error) {
	key := f.enc.key

	if kid != f.enc.kid {
		dk, ok := f.decryption[kid]
		if !ok {
			return nil, fmt.Errorf("encryption key %q: %w", kid, ErrUnknownKey)
		}

		if !at.Before(dk.retireAt) {
			return nil, fmt.Errorf("encryption key %q: %w", kid, ErrRetiredKey)
		}

		key = dk.key
	}

	secret, err := key.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("key agreement: %w", err)
	}

	return secret, nil
}
