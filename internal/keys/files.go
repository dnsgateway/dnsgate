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
		path, blockType string
		key             any
	}

	files := []keyFile{
		{filepath.Join(dir, gen.SigningKeyID+privateExt), pemPrivateKey, sigPriv},
		{filepath.Join(dir, gen.SigningKeyID+publicExt), pemPublicKey, sigPub},
		{filepath.Join(dir, gen.EncryptionKeyID+privateExt), pemPrivateKey, encPriv},
		{filepath.Join(dir, gen.EncryptionKeyID+publicExt), pemPublicKey, encPriv.PublicKey()},
	}

	if err := prepareDir(dir); err != nil {
		return Generated{}, err
	}

	for _, f := range files {
		var der []byte

		if f.blockType == pemPrivateKey {
			der, err = x509.MarshalPKCS8PrivateKey(f.key)
		} else {
			der, err = x509.MarshalPKIXPublicKey(f.key)
		}

		if err == nil {
			err = writeExclusive(f.path, pem.EncodeToMemory(&pem.Block{Type: f.blockType, Bytes: der}))
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
// keys written by Generate. A key's kid is its file name without ".pem" and
// must follow KeyIDFormat, and the file must not be readable or writable by
// group or others.
func LoadFiles(signingFile, encryptionFile string) (*Files, error) {
	sigKID, sigKey, err := readPrivateKey(signingFile, signingPrefix)
	if err != nil {
		return nil, err
	}

	sigPriv, ok := sigKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key %s is not an Ed25519 private key", signingFile)
	}

	encKID, encKey, err := readPrivateKey(encryptionFile, encryptionPrefix)
	if err != nil {
		return nil, err
	}

	encPriv, ok := encKey.(*ecdh.PrivateKey)
	if !ok || encPriv.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("encryption key %s is not an X25519 private key", encryptionFile)
	}

	return &Files{sigKID: sigKID, sigPriv: sigPriv, encKID: encKID, encPriv: encPriv}, nil
}

func readPrivateKey(path, prefix string) (string, any, error) {
	kid, ok := strings.CutSuffix(filepath.Base(path), privateExt)
	if !ok {
		return "", nil, fmt.Errorf("key file %s is not named <kid>%s", path, privateExt)
	}

	if err := checkKeyID(kid, prefix); err != nil {
		return "", nil, fmt.Errorf("key file %s: %w", path, err)
	}

	// Check the mode of the file actually read: stat and read one descriptor.
	f, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("reading key file: %w", err)
	}

	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("reading key file: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", nil, fmt.Errorf("key file %s has mode %o, want no group or other access (600)", path, perm)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return "", nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPrivateKey {
		return "", nil, fmt.Errorf("key file %s holds no PEM %q block", path, pemPrivateKey)
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
