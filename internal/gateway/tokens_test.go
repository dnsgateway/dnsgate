package gateway_test

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// appPermissions are the Permissions of a Derived Token for an
// application that manages the A records under apps in example.com.
func appPermissions() []*dnsgatev1.Permission {
	return []*dnsgatev1.Permission{{
		Verbs:  []string{"get", "list"},
		Zones:  []string{"example.com"},
		Names:  []string{"**.apps"},
		Types:  []string{"A"},
		Egress: []string{"gateway"},
	}}
}

// createToken issues a Derived Token of parent for the Service Account
// sub with perms.
func (h *harness) createToken(t *testing.T, parent, sub string, perms []*dnsgatev1.Permission) *dnsgatev1.CreateTokenResponse {
	t.Helper()

	resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{Token: parent, Sub: sub, Permissions: perms})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	return resp
}

func TestCreateTokenIssuesADerivedTokenOfTheParent(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	rootClaims, err := h.client.InspectToken(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}

	resp := h.createToken(t, root, "external-dns-prod", appPermissions())

	got, err := h.client.InspectToken(t.Context(), resp.GetToken())
	if err != nil {
		t.Fatalf("InspectToken: %v", err)
	}

	if got.GetSub() != "external-dns-prod" {
		t.Errorf("sub = %q, want external-dns-prod", got.GetSub())
	}

	if got.GetJti() != resp.GetJti() || !strings.HasPrefix(got.GetJti(), "tok_") || got.GetJti() == rootClaims.GetJti() {
		t.Errorf("jti = %q, want a new tok_ ID, as returned (%q)", got.GetJti(), resp.GetJti())
	}

	if !slices.Equal(got.GetAncestors(), []string{rootClaims.GetJti()}) {
		t.Errorf("ancestors = %v, want the Root Token's jti", got.GetAncestors())
	}

	if got.GetProvider() != "cloudflare" || got.Exp != nil || !got.GetIat().AsTime().Equal(h.now) {
		t.Errorf("token = %v, want provider cloudflare, iat now and no exp", got)
	}

	if !samePermissions(got.GetPermissions(), appPermissions()) {
		t.Errorf("permissions = %v, want %v", got.GetPermissions(), appPermissions())
	}
}

func TestOnlyATokenWithCreateOnTokensIssuesTokens(t *testing.T) {
	h := newHarness(t)

	for name, perms := range map[string][]token.Permission{
		"records only":       {{Verbs: []string{"get", "list", "create"}}},
		"other verb":         {{Verbs: []string{"get", "delete"}, Resources: []string{"records", "tokens"}}},
		"no permissions":     nil,
		"create on zones":    {{Verbs: []string{"create"}, Resources: []string{"zones"}}},
		"create, then other": {{Verbs: []string{"create"}, Resources: []string{"records"}}, {Verbs: []string{"get"}, Resources: []string{"tokens"}}},
	} {
		t.Run(name, func(t *testing.T) {
			parent := h.mint(t, nil, perms...)

			resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
				Token: parent, Sub: "app", Permissions: []*dnsgatev1.Permission{{Verbs: []string{"get"}}},
			})
			wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

			if resp.GetToken() != "" {
				t.Error("a token was returned")
			}
		})
	}

	t.Run("invalid parent", func(t *testing.T) {
		_, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
			Token: "not-a-token", Sub: "app", Permissions: []*dnsgatev1.Permission{{Verbs: []string{"get"}}},
		})
		wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
	})

	for _, e := range h.auditEvents(t) {
		if e["event"] != "token.create" || e["result"] != "denied" {
			t.Errorf("audit event = %v, want a denied token.create", e)
		}
	}
}

func TestADerivedTokenWorksWithinItsPermissionsOnly(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	derived := h.createToken(t, h.onboard(t, onboardRequest()), "app", appPermissions()).GetToken()

	resp, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: derived, Zone: "example.com", Name: "www.apps", Type: "A"})
	if err != nil {
		t.Fatalf("GetRecord within the Permissions: %v", err)
	}

	if got := resp.GetRecordSet().GetValues(); len(got) != 2 {
		t.Errorf("values = %v, want the two A records of www.apps", got)
	}

	// The Provider was built from the Parent Token's Provider Credential.
	calls := h.fake.Calls()
	if len(calls) == 0 || calls[0].Fields["token"] != cfToken {
		t.Errorf("provider calls = %+v, want it built from the Provider Credential", calls)
	}

	for name, req := range map[string]*dnsgatev1.GetRecordRequest{
		"other type": {Token: derived, Zone: "example.com", Name: "www.apps", Type: "TXT"},
		"other name": {Token: derived, Zone: "example.com", Name: "apps", Type: "A"},
		"other zone": {Token: derived, Zone: "example.org", Name: "www.apps", Type: "A"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.client.GetRecord(t.Context(), req)
			wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)
		})
	}

	_, err = h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: derived})
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)
}
