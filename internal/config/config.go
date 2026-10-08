// Package config reads the Gateway's configuration file.
package config

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// DefaultListen is the listen address of a configuration that sets none.
const DefaultListen = ":8443"

// minBootstrapSecret is the shortest bootstrap secret the Gateway accepts.
const minBootstrapSecret = 16

// File is the Gateway's configuration file, read as YAML or JSON.
// Relative file paths are resolved against the configuration file's
// directory.
type File struct {
	// Listen is the TCP address the gRPC API is served on.
	Listen string `json:"listen"`
	TLS    TLS    `json:"tls"`
	Keys   Keys   `json:"keys"`
	// BootstrapSecretFile holds the secret that authorizes Onboarding. It
	// must not be readable or writable by group or others.
	BootstrapSecretFile string `json:"bootstrapSecretFile"`
}

// TLS is the Gateway's server certificate.
type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Keys are the Gateway's signing and encryption key files, as written by
// "dnsgate keys generate".
type Keys struct {
	SigningKeyFile string `json:"signingKeyFile"`
	// EncryptionKeyFile is the current encryption key: new and resealed
	// tokens are sealed under it.
	EncryptionKeyFile string `json:"encryptionKeyFile"`
	// DecryptionKeys are older encryption keys, kept after a rotation so
	// that tokens sealed under them open until they are resealed.
	DecryptionKeys []DecryptionKey `json:"decryptionKeys"`
}

// DecryptionKey is an older encryption key and its retirement deadline.
type DecryptionKey struct {
	KeyFile string `json:"keyFile"`
	// RetireAt is an RFC 3339 time from which the key no longer opens
	// tokens. A deadline that has passed is allowed: the key then opens
	// none.
	RetireAt time.Time `json:"retireAt"`
}

// Load reads the configuration file at path. Unknown fields are errors, so
// a misspelled setting is caught at startup.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg File

	if err := yaml.UnmarshalStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}

	base := filepath.Dir(path)

	files := map[string]*string{
		"tls.certFile":           &cfg.TLS.CertFile,
		"tls.keyFile":            &cfg.TLS.KeyFile,
		"keys.signingKeyFile":    &cfg.Keys.SigningKeyFile,
		"keys.encryptionKeyFile": &cfg.Keys.EncryptionKeyFile,
		"bootstrapSecretFile":    &cfg.BootstrapSecretFile,
	}

	for i := range cfg.Keys.DecryptionKeys {
		dk := &cfg.Keys.DecryptionKeys[i]
		files[fmt.Sprintf("keys.decryptionKeys[%d].keyFile", i)] = &dk.KeyFile

		if dk.RetireAt.IsZero() {
			return nil, fmt.Errorf("config %s: keys.decryptionKeys[%d].retireAt is required", path, i)
		}
	}

	for name, p := range files {
		if *p == "" {
			return nil, fmt.Errorf("config %s: %s is required", path, name)
		}

		if !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}

	return &cfg, nil
}

// Load reads the key files: the signing key, the current encryption key
// and the decryption keys with their retirement deadlines.
func (k Keys) Load() (*keys.Files, error) {
	opts := make([]keys.Option, 0, len(k.DecryptionKeys))
	for _, dk := range k.DecryptionKeys {
		opts = append(opts, keys.WithDecryptionKey(dk.KeyFile, dk.RetireAt))
	}

	return keys.LoadFiles(k.SigningKeyFile, k.EncryptionKeyFile, opts...)
}

// BootstrapSecret reads the bootstrap secret, without surrounding
// whitespace, from BootstrapSecretFile. The file must give group and
// others no access, and the secret must be at least minBootstrapSecret
// bytes long.
func (c *File) BootstrapSecret() (token.Secret, error) {
	path := c.BootstrapSecretFile

	f, err := os.Open(path)
	if err != nil {
		return token.Secret{}, fmt.Errorf("reading bootstrap secret: %w", err)
	}

	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return token.Secret{}, fmt.Errorf("reading bootstrap secret: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return token.Secret{}, fmt.Errorf("bootstrap secret file %s has mode %o, want no group or other access (600)", path, perm)
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return token.Secret{}, fmt.Errorf("reading bootstrap secret: %w", err)
	}

	secret := bytes.TrimSpace(data)
	if len(secret) < minBootstrapSecret {
		return token.Secret{}, fmt.Errorf("bootstrap secret file %s holds fewer than %d bytes", path, minBootstrapSecret)
	}

	return token.NewSecret(string(secret)), nil
}
