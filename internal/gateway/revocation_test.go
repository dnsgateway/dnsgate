package gateway_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/durationpb"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// adminPermissions may issue and revoke tokens, and read and change
// every record.
func adminPermissions() []*dnsgatev1.Permission {
	return []*dnsgatev1.Permission{
		{Verbs: []string{"create", "delete"}, Resources: []string{"tokens"}},
		{Verbs: []string{"get", "list", "create", "update", "patch", "delete"}},
	}
}

// recordPermissions may read and change every record, and nothing else.
func recordPermissions() []*dnsgatev1.Permission {
	return []*dnsgatev1.Permission{{Verbs: []string{"get", "list", "create", "update", "patch", "delete"}}}
}

func (h *harness) revokeID(t *testing.T, tok, id string) {
	t.Helper()

	if _, err := h.client.RevokeToken(t.Context(), revokeIDRequest(tok, id)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

func revokeIDRequest(tok, id string) *dnsgatev1.RevokeTokenRequest {
	return &dnsgatev1.RevokeTokenRequest{Token: tok, Target: &dnsgatev1.RevokeTokenRequest_TokenId{TokenId: id}}
}

func revokeTokenRequest(tok, target string) *dnsgatev1.RevokeTokenRequest {
	return &dnsgatev1.RevokeTokenRequest{Token: tok, Target: &dnsgatev1.RevokeTokenRequest_TargetToken{TargetToken: target}}
}

// wantWorks checks that tok is accepted, for inspection and for listing
// example.com's records.
func (h *harness) wantWorks(t *testing.T, name, tok string) {
	t.Helper()

	if _, err := h.client.InspectToken(t.Context(), tok); err != nil {
		t.Errorf("%s: inspect: %v", name, err)
	}

	if _, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: tok, Zone: "example.com"}); err != nil {
		t.Errorf("%s: list records: %v", name, err)
	}
}

// wantRevoked checks that tok is refused as unauthenticated for every
// kind of request, and that none reaches the Provider.
func (h *harness) wantRevoked(t *testing.T, name, tok string) {
	t.Helper()

	calls := len(h.fake.Calls())

	_, err := h.client.InspectToken(t.Context(), tok)
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	_, err = h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: tok, Zone: "example.com"})
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	_, err = h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: tok, Zone: "example.com", Name: "new", Type: "A", Ttl: 300, Values: []string{"192.0.2.99"},
	})
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	_, err = h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{Token: tok, Sub: "x", Permissions: recordPermissions()})
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	_, err = h.client.ResealToken(t.Context(), tok)
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	_, err = h.client.RevokeToken(t.Context(), revokeIDRequest(tok, "tok_01ARZ3NDEKTSV4RRFFQ69G5FAV"))
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	if got := len(h.fake.Calls()); got != calls {
		t.Errorf("%s: a revoked token reached the Provider", name)
	}
}

func TestRevokedTokenFailsOnTheNextRequest(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())
	app := h.createToken(t, root, "app", recordPermissions())

	h.wantWorks(t, "app before revocation", app.GetToken())

	resp, err := h.client.RevokeToken(t.Context(), revokeIDRequest(root, app.GetJti()))
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	if resp.GetJti() != app.GetJti() {
		t.Errorf("revoked jti = %q, want %q", resp.GetJti(), app.GetJti())
	}

	h.wantRevoked(t, "app", app.GetToken())
	h.wantWorks(t, "root", root)
}

func TestRevokingAParentRevokesEveryDescendant(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())
	admin := h.createToken(t, root, "admin", adminPermissions())
	sibling := h.createToken(t, root, "sibling", adminPermissions())
	team := h.createToken(t, admin.GetToken(), "team", adminPermissions())
	app := h.createToken(t, team.GetToken(), "app", adminPermissions())
	leaf := h.createToken(t, app.GetToken(), "leaf", recordPermissions())
	cousin := h.createToken(t, sibling.GetToken(), "cousin", recordPermissions())

	h.revokeID(t, root, admin.GetJti())

	for name, tok := range map[string]string{
		"admin": admin.GetToken(), "team": team.GetToken(), "app": app.GetToken(), "leaf": leaf.GetToken(),
	} {
		h.wantRevoked(t, name, tok)
	}

	for name, tok := range map[string]string{"root": root, "sibling": sibling.GetToken(), "cousin": cousin.GetToken()} {
		h.wantWorks(t, name, tok)
	}
}

func TestRevokingARootTokenDisablesEverythingIssuedUnderItsOnboarding(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())
	rootClaims, err := h.client.InspectToken(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}

	admin := h.createToken(t, root, "admin", adminPermissions())
	app := h.createToken(t, admin.GetToken(), "app", recordPermissions())
	other := h.createToken(t, root, "other", recordPermissions())

	// Another onboarding's Root Token may revoke it: any token with delete
	// on tokens may revoke any ID (ADR 0001).
	otherRoot := h.onboard(t, onboardRequest())
	otherApp := h.createToken(t, otherRoot, "app", recordPermissions())

	h.revokeID(t, otherRoot, rootClaims.GetJti())

	for name, tok := range map[string]string{
		"root": root, "admin": admin.GetToken(), "app": app.GetToken(), "other": other.GetToken(),
	} {
		h.wantRevoked(t, name, tok)
	}

	h.wantWorks(t, "other onboarding's root", otherRoot)
	h.wantWorks(t, "other onboarding's app", otherApp.GetToken())
}

func TestATokenWithoutDeleteOnTokensCannotRevoke(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())
	issuer := h.createToken(t, root, "issuer", []*dnsgatev1.Permission{
		{Verbs: []string{"create", "get", "list", "update", "patch"}, Resources: []string{"tokens", "records", "zones"}},
	})
	app := h.createToken(t, root, "app", recordPermissions())

	for name, tok := range map[string]string{"issuer": issuer.GetToken(), "app": app.GetToken()} {
		t.Run(name, func(t *testing.T) {
			_, err := h.client.RevokeToken(t.Context(), revokeIDRequest(tok, app.GetJti()))
			wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)
		})
	}

	h.wantWorks(t, "app", app.GetToken())
}

func TestRevokedTokensStayRevokedAfterARestart(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())
	admin := h.createToken(t, root, "admin", adminPermissions())
	app := h.createToken(t, admin.GetToken(), "app", recordPermissions())
	byToken := h.createToken(t, root, "by-token", recordPermissions())

	h.revokeID(t, root, admin.GetJti())

	if _, err := h.client.RevokeToken(t.Context(), revokeTokenRequest(root, byToken.GetToken())); err != nil {
		t.Fatal(err)
	}

	h.restart(t)

	h.wantRevoked(t, "admin", admin.GetToken())
	h.wantRevoked(t, "app", app.GetToken())
	h.wantRevoked(t, "by-token", byToken.GetToken())
	h.wantWorks(t, "root", root)
}

// TestRevocationIsKeptUntilTheRevokedTokenExpires revokes tokens by their
// ID and by the token itself, and checks how long the store keeps each
// revocation: given the token, until its expiry; given only an ID, whose
// expiry the Gateway cannot know, forever.
func TestRevocationIsKeptUntilTheRevokedTokenExpires(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	expiring := func(sub string) *dnsgatev1.CreateTokenResponse {
		resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
			Token: root, Sub: sub, Permissions: recordPermissions(), Expires: durationpb.New(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}

		return resp
	}

	byToken := expiring("by-token")
	byID := expiring("by-id")
	forever := h.createToken(t, root, "forever", recordPermissions())

	for _, target := range []string{byToken.GetToken(), forever.GetToken()} {
		if _, err := h.client.RevokeToken(t.Context(), revokeTokenRequest(root, target)); err != nil {
			t.Fatal(err)
		}
	}

	h.revokeID(t, root, byID.GetJti())

	purge := func(at time.Time) {
		t.Helper()

		if err := h.revocations.PurgeExpired(t.Context(), at); err != nil {
			t.Fatal(err)
		}
	}

	revoked := func(id string) bool {
		t.Helper()

		got, err := h.revocations.AnyRevoked(t.Context(), []string{id})
		if err != nil {
			t.Fatal(err)
		}

		return got
	}

	purge(h.now.Add(time.Hour - time.Second))

	if !revoked(byToken.GetJti()) {
		t.Error("a revocation was purged before its token expired")
	}

	purge(h.now.Add(time.Hour))

	for name, tc := range map[string]struct {
		id   string
		kept bool
	}{
		"revoked by token, expired":       {byToken.GetJti(), false},
		"revoked by ID, expired":          {byID.GetJti(), true},
		"revoked by token, never expires": {forever.GetJti(), true},
	} {
		if got := revoked(tc.id); got != tc.kept {
			t.Errorf("%s: kept = %v, want %v", name, got, tc.kept)
		}
	}
}

func TestRevokeRefusesMalformedTargets(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	expiringReq := onboardRequest()
	expiringReq.Expires = durationpb.New(time.Hour)
	expiring := h.onboard(t, expiringReq)

	h.now = h.now.Add(time.Hour)

	for name, req := range map[string]*dnsgatev1.RevokeTokenRequest{
		"no target":            {Token: root},
		"empty ID":             revokeIDRequest(root, ""),
		"ID without prefix":    revokeIDRequest(root, "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
		"ID not a ULID":        revokeIDRequest(root, "tok_not-a-ulid"),
		"token as ID":          revokeIDRequest(root, root),
		"target does not open": revokeTokenRequest(root, "not-a-token"),
		"target expired":       revokeTokenRequest(root, expiring),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.client.RevokeToken(t.Context(), req)
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)
		})
	}
}

func TestRevokeAndItsDenialsAreAuditedWithoutSecrets(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())
	rootClaims, err := h.client.InspectToken(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}

	app := h.createToken(t, root, "app", recordPermissions())
	target := h.createToken(t, root, "target", recordPermissions())
	start := len(h.auditEvents(t))

	// A denied caller learns nothing of the target, and its event names
	// none: the target is only parsed, or opened, once the presented token
	// may revoke.
	//
	// Denied: app lacks delete on tokens.
	_, err = h.client.RevokeToken(t.Context(), revokeTokenRequest(app.GetToken(), target.GetToken()))
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

	// Denied: the presented token does not open.
	_, err = h.client.RevokeToken(t.Context(), revokeIDRequest(root+"x", target.GetJti()))
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	if _, err := h.client.RevokeToken(t.Context(), revokeTokenRequest(root, target.GetToken())); err != nil {
		t.Fatal(err)
	}

	events := h.auditEvents(t)[start:]
	if len(events) != 3 {
		t.Fatalf("audit events = %v, want three token.revoke events", events)
	}

	want := []map[string]any{
		{
			"event": "token.revoke", "verb": "delete", "result": "denied", "category": "permission_denied",
			"service_account": "app", "jti": app.GetJti(), "provider": "cloudflare", "revoked_jti": nil,
		},
		{
			"event": "token.revoke", "verb": "delete", "result": "denied", "category": "unauthenticated",
			"service_account": nil, "jti": nil, "revoked_jti": nil,
		},
		{
			"event": "token.revoke", "verb": "delete", "result": "ok", "category": nil,
			"service_account": "root", "jti": rootClaims.GetJti(), "provider": "cloudflare", "revoked_jti": target.GetJti(),
		},
	}

	for i, e := range events {
		for field, v := range want[i] {
			if e[field] != v {
				t.Errorf("event %d: %s = %v, want %v", i, field, e[field], v)
			}
		}
	}

	for _, secret := range []string{cfToken, root, app.GetToken(), target.GetToken()} {
		if strings.Contains(h.audit.String(), secret) {
			t.Errorf("audit log contains a secret:\n%s", h.audit.String())
		}
	}
}

// TestRevocationTakesEffectEvenWhenItsAuditEventIsLost: unlike issuing a
// token, revoking one only takes access away, so a lost audit event never
// holds it back.
func TestRevocationTakesEffectEvenWhenItsAuditEventIsLost(t *testing.T) {
	h := newHarnessAuditingTo(t, failingWriter{})

	// The harness cannot onboard without an audit log; mint stands in.
	tok := h.mint(t, nil, token.Permission{Verbs: []string{"get", "delete"}, Resources: []string{"tokens"}})

	if _, err := h.client.RevokeToken(t.Context(), revokeTokenRequest(tok, tok)); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	_, err := h.client.InspectToken(t.Context(), tok)
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
}

// TestARevokedTokenIsRefusedBeforeItIsResealed: the revocation check comes
// before Resealing, so a revoked token is refused as revoked even when the
// Gateway could not seal it anyway.
func TestARevokedTokenIsRefusedBeforeItIsResealed(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())
	app := h.createToken(t, root, "app", recordPermissions())
	h.revokeID(t, root, app.GetJti())

	h.serve(t, unusableEncryptionKey{Source: h.loadKeys(t, "enc-test")})

	_, err := h.client.ResealToken(t.Context(), app.GetToken())
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
}
