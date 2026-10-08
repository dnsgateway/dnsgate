package gateway_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
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
