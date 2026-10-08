package token_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/token"
)

var testNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

const testCredential = "cf-api-token-very-secret-value"

// newKeys generates a fresh key pair set with the given kid suffix.
func newKeys(t *testing.T, suffix string) *keys.Files {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "keys")

	if _, err := keys.Generate(dir, suffix); err != nil {
		t.Fatal(err)
	}

	src, err := keys.LoadFiles(filepath.Join(dir, "sig-"+suffix+".pem"), filepath.Join(dir, "enc-"+suffix+".pem"))
	if err != nil {
		t.Fatal(err)
	}

	return src
}

func newCodec(src keys.Source) *token.Codec {
	return token.NewCodec(src, token.WithClock(func() time.Time { return testNow }))
}

func derivedClaims() token.Claims {
	exp := token.NewNumericDate(testNow.Add(24 * time.Hour))

	// No iss or aud: the Codec sets them.
	return token.Claims{
		Subject:   "external-dns-prod",
		ID:        "tok_01JCHILD",
		IssuedAt:  token.NewNumericDate(testNow),
		NotBefore: token.NewNumericDate(testNow),
		Expiry:    &exp,
		Ancestors: []string{"tok_01JROOT"},
		Provider:  "cloudflare",
		Credential: token.Credential{
			Type:  "api-token",
			Value: token.NewSecret(testCredential),
		},
		Permissions: []token.Permission{
			{
				Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
				Resources: []string{"records"},
				Zones:     []string{"example.com"},
				Names:     []string{"*.apps"},
				Types:     []string{"A", "AAAA", "TXT"},
				Egress:    []string{"agent"},
			},
			{
				// Left-out filters stay left out; an empty list stays empty.
				Verbs: []string{"get"},
				Types: []string{},
			},
		},
	}
}

func TestSealThenOpenRoundTripsClaims(t *testing.T) {
	ctx := context.Background()
	codec := newCodec(newKeys(t, "2026-10"))

	for name, claims := range map[string]token.Claims{
		"derived token": derivedClaims(),
		"root token without expiry or ancestors": func() token.Claims {
			c := derivedClaims()
			c.Expiry, c.Ancestors = nil, nil

			return c
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			sealed, err := codec.Seal(ctx, claims)
			if err != nil {
				t.Fatal(err)
			}

			opened, err := codec.Open(ctx, sealed)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(opened, claims) {
				t.Errorf("opened claims = %#v\nwant %#v", opened, claims)
			}

			if got := opened.Credential.Value.Reveal(); got != testCredential {
				t.Errorf("opened credential = %q, want the sealed one", got)
			}
		})
	}
}

// loadMixed loads the signing key of one key set and the encryption key of
// another.
func loadMixed(t *testing.T, sigDir, sigSuffix, encDir, encSuffix string) *keys.Files {
	t.Helper()

	src, err := keys.LoadFiles(filepath.Join(sigDir, "sig-"+sigSuffix+".pem"), filepath.Join(encDir, "enc-"+encSuffix+".pem"))
	if err != nil {
		t.Fatal(err)
	}

	return src
}

func generate(t *testing.T, suffix string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "keys")

	if _, err := keys.Generate(dir, suffix); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestOpenRejectsForeignAndTamperedTokens(t *testing.T) {
	ctx := context.Background()

	gateway := generate(t, "2026-10")
	other := generate(t, "2026-10") // same kids, different keys
	rotated := generate(t, "2026-11")

	opener := newCodec(loadMixed(t, gateway, "2026-10", gateway, "2026-10"))

	seal := func(t *testing.T, src keys.Source, claims token.Claims) string {
		t.Helper()

		sealed, err := newCodec(src).Seal(ctx, claims)
		if err != nil {
			t.Fatal(err)
		}

		return sealed
	}

	good := seal(t, loadMixed(t, gateway, "2026-10", gateway, "2026-10"), derivedClaims())

	tamper := func(segment int) string {
		parts := strings.Split(good, ".")
		b := []byte(parts[segment])
		// Flip a character in the middle, keeping it valid base64url.
		i := len(b) / 2
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}

		parts[segment] = string(b)

		return strings.Join(parts, ".")
	}

	withClaims := func(edit func(*token.Claims)) string {
		c := derivedClaims()
		edit(&c)

		return seal(t, loadMixed(t, gateway, "2026-10", gateway, "2026-10"), c)
	}

	cases := map[string]struct {
		token      string
		unknownKey bool
	}{
		"tampered header":              {token: tamper(0)},
		"tampered encrypted key":       {token: tamper(1)},
		"tampered ciphertext":          {token: tamper(3)},
		"tampered tag":                 {token: tamper(4)},
		"not a token":                  {token: "not-a-token"},
		"signed with a different key":  {token: seal(t, loadMixed(t, other, "2026-10", gateway, "2026-10"), derivedClaims())},
		"encrypted to a different key": {token: seal(t, loadMixed(t, gateway, "2026-10", other, "2026-10"), derivedClaims())},
		"unknown signing kid":          {token: seal(t, loadMixed(t, rotated, "2026-11", gateway, "2026-10"), derivedClaims()), unknownKey: true},
		"unknown encryption kid":       {token: seal(t, loadMixed(t, gateway, "2026-10", rotated, "2026-11"), derivedClaims()), unknownKey: true},
		"not valid yet":                {token: withClaims(func(c *token.Claims) { c.NotBefore = token.NewNumericDate(testNow.Add(time.Minute)) })},
		"expired":                      {token: withClaims(func(c *token.Claims) { e := token.NewNumericDate(testNow); c.Expiry = &e })},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := opener.Open(ctx, tc.token)
			if !errors.Is(err, token.ErrInvalid) {
				t.Fatalf("Open error = %v, want ErrInvalid", err)
			}

			if tc.unknownKey && !errors.Is(err, keys.ErrUnknownKey) {
				t.Errorf("Open error = %v, want it to wrap ErrUnknownKey", err)
			}

			// Errors carry nothing taken from the token, not even a kid.
			for _, leak := range []string{testCredential, "2026-10", "2026-11"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("Open error reveals %q: %v", leak, err)
				}
			}
		})
	}

	if _, err := opener.Open(ctx, good); err != nil {
		t.Errorf("untampered token does not open: %v", err)
	}
}

func TestOuterHeaderIsTheOnlyReadablePart(t *testing.T) {
	ctx := context.Background()
	codec := newCodec(newKeys(t, "2026-10"))

	sealed, err := codec.Seal(ctx, derivedClaims())
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(sealed, ".")
	if len(parts) != 5 {
		t.Fatalf("token has %d parts, want a 5-part compact JWE", len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}

	// typ, alg, enc and kid, plus the ephemeral public key ECDH-ES requires.
	want := map[string]any{"typ": "dnsgate+jwe", "alg": "ECDH-ES+A256KW", "enc": "A256GCM", "kid": "enc-2026-10"}

	for name, value := range header {
		if name == "epk" {
			continue
		}

		if want[name] != value {
			t.Errorf("header %q = %v, want %v", name, value, want[name])
		}
	}

	for name := range want {
		if _, ok := header[name]; !ok {
			t.Errorf("header %q missing", name)
		}
	}

	epk, ok := header["epk"].(map[string]any)
	if !ok || len(epk) != 3 || epk["kty"] != "OKP" || epk["crv"] != "X25519" || epk["x"] == "" {
		t.Errorf("epk = %v, want an X25519 public key {kty, crv, x}", header["epk"])
	}

	for _, secret := range []string{testCredential, "external-dns-prod", "example.com", "tok_01JCHILD", "sig-2026-10"} {
		if strings.Contains(sealed, secret) || strings.Contains(string(raw), secret) {
			t.Errorf("token reveals %q", secret)
		}
	}
}

// TestDecryptionKeyRetiresOnTheCodecClock checks that a Decryption Key's
// Retirement Deadline is judged by the same clock as nbf and exp, not by the
// wall clock.
func TestDecryptionKeyRetiresOnTheCodecClock(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "keys")

	for _, suffix := range []string{"2026-10", "2026-11"} {
		if _, err := keys.Generate(dir, suffix); err != nil {
			t.Fatal(err)
		}
	}

	wall := time.Now()

	for name, tc := range map[string]struct {
		retireAt, clock time.Time
		opens           bool
	}{
		"deadline passed on the wall clock only":  {retireAt: wall.Add(-24 * time.Hour), clock: wall.Add(-25 * time.Hour), opens: true},
		"deadline passed on the codec clock only": {retireAt: wall.Add(24 * time.Hour), clock: wall.Add(24 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			now := func() time.Time { return tc.clock }

			claims := derivedClaims()
			claims.NotBefore, claims.Expiry = token.NewNumericDate(tc.clock.Add(-time.Hour)), nil

			sealed, err := token.NewCodec(loadMixed(t, dir, "2026-10", dir, "2026-10"), token.WithClock(now)).Seal(ctx, claims)
			if err != nil {
				t.Fatal(err)
			}

			src, err := keys.LoadFiles(filepath.Join(dir, "sig-2026-10.pem"), filepath.Join(dir, "enc-2026-11.pem"),
				keys.WithDecryptionKey(filepath.Join(dir, "enc-2026-10.pem"), tc.retireAt))
			if err != nil {
				t.Fatal(err)
			}

			_, err = token.NewCodec(src, token.WithClock(now)).Open(ctx, sealed)

			switch {
			case tc.opens && err != nil:
				t.Errorf("Open before the deadline on the codec clock: %v", err)
			case !tc.opens && !errors.Is(err, keys.ErrRetiredKey):
				t.Errorf("Open after the deadline on the codec clock error = %v, want ErrRetiredKey", err)
			}
		})
	}
}
