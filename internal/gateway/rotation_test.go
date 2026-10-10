package gateway_test

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dnsgateway/dnsgate/internal/keys"
)

// outerKeyID returns the kid in a Service Token's readable JWE header.
func outerKeyID(t *testing.T, tok string) string {
	t.Helper()

	header, _, _ := strings.Cut(tok, ".")

	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("token header: %v", err)
	}

	var h struct {
		Kid string `json:"kid"`
	}

	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("token header: %v", err)
	}

	return h.Kid
}

func TestRotatedKeyOpensOldTokensUntilItsRetirementDeadline(t *testing.T) {
	h := newHarness(t)

	old := h.onboard(t, onboardRequest())
	if kid := outerKeyID(t, old); kid != "enc-test" {
		t.Fatalf("token kid before rotation = %q, want enc-test", kid)
	}

	retireAt := h.now.Add(30 * 24 * time.Hour)
	newKID := h.rotate(t, retireAt)

	if kid := outerKeyID(t, h.onboard(t, onboardRequest())); kid != newKID {
		t.Errorf("new token kid = %q, want %q", kid, newKID)
	}

	h.now = retireAt.Add(-time.Second)

	if _, err := h.client.InspectToken(t.Context(), old); err != nil {
		t.Errorf("old token before the retirement deadline: %v", err)
	}

	h.now = retireAt

	_, err := h.client.InspectToken(t.Context(), old)
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
}

func (h *harness) reseal(t *testing.T, tok string) string {
	t.Helper()

	resp, err := h.client.ResealToken(t.Context(), tok)
	if err != nil {
		t.Fatalf("ResealToken: %v", err)
	}

	return resp.GetToken()
}

func TestResealedTokenCarriesTheNewKeyAndSameClaimsAndOutlivesTheOldKey(t *testing.T) {
	h := newHarness(t)

	req := onboardRequest()
	req.Expires = durationpb.New(90 * 24 * time.Hour)
	old := h.onboard(t, req)

	want, err := h.client.InspectToken(t.Context(), old)
	if err != nil {
		t.Fatal(err)
	}

	retireAt := h.now.Add(30 * 24 * time.Hour)
	newKID := h.rotate(t, retireAt)

	h.now = h.now.Add(time.Hour)
	resealed := h.reseal(t, old)

	if kid := outerKeyID(t, resealed); kid != newKID {
		t.Errorf("resealed token kid = %q, want %q", kid, newKID)
	}

	h.now = retireAt

	got, err := h.client.InspectToken(t.Context(), resealed)
	if err != nil {
		t.Fatalf("resealed token after the old key retired: %v", err)
	}

	if !proto.Equal(got, want) {
		t.Errorf("resealed token claims = %v, want the original %v", got, want)
	}

	_, err = h.client.InspectToken(t.Context(), old)
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
}

func TestResealRejectsTokensThatDoNotOpen(t *testing.T) {
	h := newHarness(t)

	req := onboardRequest()
	req.Expires = durationpb.New(time.Hour)
	expiring := h.onboard(t, req)
	retiring := h.onboard(t, onboardRequest())

	retireAt := h.now.Add(2 * time.Hour)
	h.rotate(t, retireAt)
	h.now = retireAt

	for name, tok := range map[string]string{
		"empty":                    "",
		"garbage":                  "not-a-token",
		"tampered":                 retiring[:len(retiring)-4] + "AAAA",
		"expired":                  expiring,
		"sealed under retired key": retiring,
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := h.client.ResealToken(t.Context(), tok)
			wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

			if resp.GetToken() != "" {
				t.Error("a token was returned")
			}
		})
	}
}

func TestResealWritesAuditEventsWithoutSecrets(t *testing.T) {
	h := newHarness(t)

	old := h.onboard(t, onboardRequest())

	got, err := h.client.InspectToken(t.Context(), old)
	if err != nil {
		t.Fatal(err)
	}

	h.rotate(t, h.now.Add(time.Hour))

	resealed := h.reseal(t, old)

	_, err = h.client.ResealToken(t.Context(), old+"x")
	if err == nil {
		t.Fatal("resealing a tampered token succeeded")
	}

	var reseals []map[string]any

	for _, e := range h.auditEvents(t) {
		if e["event"] == "token.reseal" {
			reseals = append(reseals, e)
		}
	}

	if len(reseals) != 2 {
		t.Fatalf("token.reseal audit events = %v, want two", reseals)
	}

	for field, want := range map[string]any{
		"jti":             got.GetJti(),
		"service_account": "root",
		"provider":        "cloudflare",
		"result":          "ok",
		"old_kid":         "enc-test",
		"new_kid":         "enc-next",
	} {
		if reseals[0][field] != want {
			t.Errorf("audit %s = %v, want %v", field, reseals[0][field], want)
		}
	}

	if e := reseals[1]; e["result"] != "denied" || e["category"] != "unauthenticated" {
		t.Errorf("audit event = %v, want a denied token.reseal, category unauthenticated", e)
	}

	for _, secret := range []string{cfToken, old, resealed} {
		if strings.Contains(h.audit.String(), secret) || strings.Contains(err.Error(), secret) {
			t.Errorf("audit log or error contains a secret:\n%s\n%v", h.audit.String(), err)
		}
	}
}

// unusableEncryptionKey is a key Source whose current encryption key is a
// low-order X25519 point, so sealing under it fails while opening still
// works.
type unusableEncryptionKey struct {
	keys.Source
}

func (unusableEncryptionKey) EncryptionKey() (string, *ecdh.PublicKey) {
	pub, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		panic(err)
	}

	return "enc-broken", pub
}

func TestResealReportsAnInternalErrorWhenSealingFails(t *testing.T) {
	h := newHarness(t)
	old := h.onboard(t, onboardRequest())

	h.serve(t, unusableEncryptionKey{Source: h.loadKeys(t, "enc-test")})

	resp, err := h.client.ResealToken(t.Context(), old)
	wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

	if resp.GetToken() != "" {
		t.Error("a token was returned")
	}
}

func TestResealReturnsNoTokenWhenItsAuditEventIsLost(t *testing.T) {
	h := newHarness(t)
	old := h.onboard(t, onboardRequest())

	h.auditTo = failingWriter{}
	h.rotate(t, h.now.Add(time.Hour))

	resp, err := h.client.ResealToken(t.Context(), old)
	wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

	if resp.GetToken() != "" {
		t.Error("a resealed token was returned without its audit event")
	}
}
