package token

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/keys"
)

// TestOpenRejectsForeignIssuerOrAudience seals iss and aud values Seal never
// writes, as another issuer sharing the keys would.
func TestOpenRejectsForeignIssuerOrAudience(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "keys")

	if _, err := keys.Generate(dir, "2026-10"); err != nil {
		t.Fatal(err)
	}

	src, err := keys.LoadFiles(filepath.Join(dir, "sig-2026-10.pem"), filepath.Join(dir, "enc-2026-10.pem"))
	if err != nil {
		t.Fatal(err)
	}

	codec := NewCodec(src)

	for name, wire := range map[string]wireClaims{
		"wrong issuer":   {Issuer: "someone-else", Audience: Audience},
		"wrong audience": {Issuer: Issuer, Audience: "someone-else"},
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := codec.seal(ctx, wire)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := codec.Open(ctx, sealed); !errors.Is(err, ErrInvalid) {
				t.Errorf("Open error = %v, want ErrInvalid", err)
			}
		})
	}
}
