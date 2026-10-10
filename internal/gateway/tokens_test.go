package gateway_test

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

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

// wantNarrowingViolation checks that err is a narrowing violation naming
// dimension.
func wantNarrowingViolation(t *testing.T, err error, dimension string) {
	t.Helper()

	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_NARROWING_VIOLATION)

	if got := dnsgatev1.ErrorDetail(status.Convert(err)).GetDimension(); got != dimension {
		t.Errorf("dimension = %q, want %q", got, dimension)
	}
}

func TestCreateTokenRejectsWiderPermissions(t *testing.T) {
	h := newHarness(t)

	parent := h.createToken(t, h.onboard(t, onboardRequest()), "intermediate", []*dnsgatev1.Permission{
		{Verbs: []string{"create"}, Resources: []string{"tokens"}},
		appPermissions()[0],
	}).GetToken()

	for dimension, perm := range map[string]*dnsgatev1.Permission{
		"verbs":     {Verbs: []string{"get", "delete"}, Zones: []string{"example.com"}, Names: []string{"**.apps"}, Types: []string{"A"}, Egress: []string{"gateway"}},
		"resources": {Verbs: []string{"get"}, Resources: []string{"zones"}, Egress: []string{"gateway"}},
		"egress":    {Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"**.apps"}, Types: []string{"A"}},
		"zones":     {Verbs: []string{"get"}, Zones: []string{"*"}, Names: []string{"**.apps"}, Types: []string{"A"}, Egress: []string{"gateway"}},
		"types":     {Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"**.apps"}, Egress: []string{"gateway"}},
		"names":     {Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"@"}, Types: []string{"A"}, Egress: []string{"gateway"}},
	} {
		t.Run(dimension, func(t *testing.T) {
			resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
				Token: parent, Sub: "app", Permissions: []*dnsgatev1.Permission{perm},
			})
			wantNarrowingViolation(t, err, dimension)

			if resp.GetToken() != "" {
				t.Error("a token was returned")
			}
		})
	}

	t.Run("create on tokens with a parent that has it", func(t *testing.T) {
		h.createToken(t, parent, "app", []*dnsgatev1.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}})
	})

	t.Run("delete on tokens with a parent that has only create", func(t *testing.T) {
		_, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
			Token: parent, Sub: "app", Permissions: []*dnsgatev1.Permission{{Verbs: []string{"create", "delete"}, Resources: []string{"tokens"}}},
		})
		wantNarrowingViolation(t, err, "verbs")
	})
}

// issuing is perms and a rule granting create on tokens, so that a token
// holding them may issue Derived Tokens.
func issuing(perms ...token.Permission) []token.Permission {
	return append(perms, token.Permission{Verbs: []string{"create"}, Resources: []string{"tokens"}})
}

// narrowingCase is a Derived Token request under a Parent Token, and its
// outcome: want is "" if the token is issued, else the dimension of the
// narrowing violation; refused is the category of any other refusal.
type narrowingCase struct {
	parent  []token.Permission
	derived []*dnsgatev1.Permission
	want    string
	refused dnsgatev1.Error_Category
}

// check asks for the Derived Token of tc and checks its outcome.
func (tc narrowingCase) check(t *testing.T, h *harness) {
	t.Helper()

	resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
		Token: h.mint(t, nil, tc.parent...), Sub: "app", Permissions: tc.derived,
	})

	switch {
	case tc.refused != dnsgatev1.Error_CATEGORY_UNSPECIFIED:
		if got := dnsgatev1.ErrorDetail(status.Convert(err)).GetCategory(); got != tc.refused {
			t.Errorf("CreateToken error = %v, want category %v", err, tc.refused)
		}
	case tc.want != "":
		wantNarrowingViolation(t, err, tc.want)
	case err != nil:
		t.Errorf("CreateToken: %v", err)
	}

	if (err == nil) != (resp.GetToken() != "") {
		t.Errorf("CreateToken returned token %q with error %v", resp.GetToken(), err)
	}
}

func TestNarrowingCoversNamePatterns(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		parent  []string
		derived string
		want    bool
	}{
		{[]string{"@"}, "@", true},
		{[]string{"@"}, "www", false},
		{[]string{"www"}, "@", false},
		{[]string{"www"}, "www", true},
		{[]string{"WWW"}, "www", true},
		{[]string{"www"}, "*", false},
		{[]string{"*"}, "www", true},
		{[]string{"*"}, "@", false},
		{[]string{"*"}, "*", true},
		{[]string{"*"}, "**", false},
		{[]string{"*"}, "www.apps", false},
		{[]string{"**"}, "@", false},
		{[]string{"**"}, "www", true},
		{[]string{"**"}, "*", true},
		{[]string{"**"}, "a.b.c", true},
		{[]string{"**"}, "**.*", true},
		{[]string{"*.apps"}, "www.apps", true},
		{[]string{"*.apps"}, "*.apps", true},
		{[]string{"*.apps"}, "**.apps", false},
		{[]string{"*.apps"}, "apps", false},
		{[]string{"**.apps"}, "*.apps", true},
		{[]string{"**.apps"}, "a.*.apps", true},
		{[]string{"**.apps"}, "**.apps", true},
		{[]string{"**.apps"}, "apps", false},
		{[]string{"**.apps"}, "**", false},
		{[]string{"*.**"}, "**.**", true},
		{[]string{"*.**"}, "**", false},
		{[]string{"**.**"}, "*.**", true},
		{[]string{"a.**.z"}, "a.b.*.z", true},
		{[]string{"a.**.z"}, "a.z", false},
		{[]string{"_acme-challenge.**"}, "_acme-challenge", false},
		{[]string{"_acme-challenge", "_acme-challenge.**"}, "_acme-challenge", true},
		// A parent rule that leaves names out allows every name.
		{nil, "www", true},

		// A pattern may be covered only by several parent patterns together.
		{[]string{"@", "**"}, "@", true},
		{[]string{"*", "*.**"}, "**", true},
		{[]string{"*", "*.*"}, "**", false},
		{[]string{"www.*", "*.*"}, "*.*", true},
		{[]string{"a.*", "*.b"}, "*.*", false},
	} {
		t.Run(fmt.Sprintf("%q covers %q", tc.parent, tc.derived), func(t *testing.T) {
			want := "names"
			if tc.want {
				want = ""
			}

			narrowingCase{
				parent:  issuing(token.Permission{Verbs: []string{"get"}, Names: tc.parent}),
				derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Names: []string{tc.derived}}},
				want:    want,
			}.check(t, h)
		})
	}
}

func TestNarrowingCoversEachDimension(t *testing.T) {
	h := newHarness(t)

	root := []token.Permission{{
		Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
		Resources: []string{"zones", "records", "tokens"},
		Zones:     []string{"*"},
		Names:     []string{"@", "**"},
		Types:     []string{"*"},
		Egress:    []string{"gateway", "agent"},
	}}
	records := issuing(token.Permission{
		Verbs:  []string{"get", "list"},
		Zones:  []string{"example.com"},
		Names:  []string{"**.apps"},
		Types:  []string{"A", "TXT"},
		Egress: []string{"gateway"},
	})

	for name, tc := range map[string]narrowingCase{
		"root covers itself": {parent: root, derived: []*dnsgatev1.Permission{{
			Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
			Resources: []string{"zones", "records", "tokens"},
			Zones:     []string{"*"}, Names: []string{"@", "**"}, Types: []string{"*"}, Egress: []string{"gateway", "agent"},
		}}},
		"root covers every filter left out": {parent: root, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}}}},
		"root covers tokens":                {parent: root, derived: []*dnsgatev1.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}}},
		"filters left out on both": {
			parent:  issuing(token.Permission{Verbs: []string{"get"}}),
			derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}}},
		},
		// A request must hold rules, each with verbs.
		"no derived rules":           {parent: records, refused: dnsgatev1.Error_CATEGORY_INVALID_REQUEST},
		"derived rule without verbs": {parent: records, derived: []*dnsgatev1.Permission{{Zones: []string{"example.org"}}}, refused: dnsgatev1.Error_CATEGORY_INVALID_REQUEST},
		"equal rules": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get", "list"}, Zones: []string{"example.com"}, Names: []string{"**.apps"}, Types: []string{"A", "TXT"}, Egress: []string{"gateway"},
		}}},
		"narrower on every filter": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Resources: []string{"records"}, Zones: []string{"Example.COM."},
			Names: []string{"www.apps", "*.*.apps"}, Types: []string{"txt"}, Egress: []string{"gateway"},
		}}},
		"rules add up across parent rules": {
			parent: issuing(
				token.Permission{Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"*"}},
				token.Permission{Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"*.**"}},
				token.Permission{Verbs: []string{"list"}, Zones: []string{"example.com"}},
			),
			derived: []*dnsgatev1.Permission{{Verbs: []string{"get", "list"}, Zones: []string{"example.com"}, Names: []string{"**"}}},
		},

		"other verb":     {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"delete"}, Zones: []string{"example.com"}}}, want: "verbs"},
		"other resource": {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Resources: []string{"zones"}}}, want: "resources"},
		// A parent without create on tokens issues no tokens at all.
		"create on tokens without the parent having it": {
			parent:  []token.Permission{{Verbs: []string{"create"}, Resources: []string{"records"}}},
			derived: []*dnsgatev1.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}},
			refused: dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"resources left out means records": {
			parent:  issuing(token.Permission{Verbs: []string{"get"}, Resources: []string{"zones"}}),
			derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}}},
			want:    "resources",
		},
		"egress left out is any": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"www.apps"}, Types: []string{"A"},
		}}, want: "egress"},
		"other egress":          {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Egress: []string{"agent"}}}, want: "egress"},
		"zones left out is any": {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Egress: []string{"gateway"}}}, want: "zones"},
		"zone star":             {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Zones: []string{"*"}, Egress: []string{"gateway"}}}, want: "zones"},
		"other zone":            {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Zones: []string{"example.org"}, Egress: []string{"gateway"}}}, want: "zones"},
		"types left out is any": {parent: records, derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Zones: []string{"example.com"}, Egress: []string{"gateway"}}}, want: "types"},
		"type star": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"*"}, Egress: []string{"gateway"},
		}}, want: "types"},
		"other type": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"MX"}, Egress: []string{"gateway"},
		}}, want: "types"},
		"names left out is any": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}, Egress: []string{"gateway"},
		}}, want: "names"},
		"wider name": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}, Names: []string{"**"}, Egress: []string{"gateway"},
		}}, want: "names"},
		"apex outside the patterns": {parent: records, derived: []*dnsgatev1.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}, Names: []string{"@"}, Egress: []string{"gateway"},
		}}, want: "names"},
		"one parent rule must cover each zone and type": {
			parent: issuing(
				token.Permission{Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}},
				token.Permission{Verbs: []string{"get"}, Zones: []string{"example.org"}, Types: []string{"TXT"}},
			),
			derived: []*dnsgatev1.Permission{{Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"TXT"}}},
			want:    "types",
		},
	} {
		t.Run(name, func(t *testing.T) { tc.check(t, h) })
	}
}

func TestCreateTokenRejectsALaterExpiry(t *testing.T) {
	h := newHarness(t)

	req := onboardRequest()
	req.Expires = durationpb.New(48 * time.Hour)
	expiring := h.onboard(t, req)
	forever := h.onboard(t, onboardRequest())

	create := func(parent string, expires *durationpb.Duration) (*dnsgatev1.CreateTokenResponse, error) {
		return h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
			Token: parent, Sub: "app", Permissions: appPermissions(), Expires: expires,
		})
	}

	exp := func(t *testing.T, resp *dnsgatev1.CreateTokenResponse) *time.Time {
		t.Helper()

		got, err := h.client.InspectToken(t.Context(), resp.GetToken())
		if err != nil {
			t.Fatal(err)
		}

		if got.Exp == nil {
			return nil
		}

		e := got.GetExp().AsTime()

		return &e
	}

	t.Run("earlier", func(t *testing.T) {
		resp, err := create(expiring, durationpb.New(time.Hour))
		if err != nil {
			t.Fatal(err)
		}

		if got := exp(t, resp); got == nil || !got.Equal(h.now.Add(time.Hour)) {
			t.Errorf("exp = %v, want in an hour", got)
		}
	})

	t.Run("equal", func(t *testing.T) {
		if _, err := create(expiring, durationpb.New(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("later", func(t *testing.T) {
		_, err := create(expiring, durationpb.New(48*time.Hour+time.Second))
		wantNarrowingViolation(t, err, "exp")
	})

	t.Run("none, with a parent that expires", func(t *testing.T) {
		_, err := create(expiring, nil)
		wantNarrowingViolation(t, err, "exp")
	})

	t.Run("none, with a parent that never expires", func(t *testing.T) {
		resp, err := create(forever, nil)
		if err != nil {
			t.Fatal(err)
		}

		if got := exp(t, resp); got != nil {
			t.Errorf("exp = %v, want none", got)
		}
	})

	t.Run("any, with a parent that never expires", func(t *testing.T) {
		if _, err := create(forever, durationpb.New(24*365*time.Hour)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("under a second", func(t *testing.T) {
		if _, err := create(forever, durationpb.New(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	})

	for name, d := range map[string]time.Duration{"zero": 0, "negative": -time.Hour} {
		t.Run(name, func(t *testing.T) {
			_, err := create(forever, durationpb.New(d))
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)
		})
	}
}

func TestAncestorsGrowWithEachLevel(t *testing.T) {
	h := newHarness(t)

	issuer := []*dnsgatev1.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}, appPermissions()[0]}

	tok := h.onboard(t, onboardRequest())

	var want []string

	for level := range 4 {
		claims, err := h.client.InspectToken(t.Context(), tok)
		if err != nil {
			t.Fatal(err)
		}

		if !slices.Equal(claims.GetAncestors(), want) {
			t.Fatalf("level %d ancestors = %v, want %v", level, claims.GetAncestors(), want)
		}

		want = append(want, claims.GetJti())
		tok = h.createToken(t, tok, "level", issuer).GetToken()
	}
}

// issueAtDepth issues a Derived Token of a parent with ancestors
// ancestors, holding create on tokens, and returns it and the error.
func (h *harness) issueAtDepth(t *testing.T, ancestors int) (*dnsgatev1.CreateTokenResponse, error) {
	t.Helper()

	issuer := token.Permission{Verbs: []string{"create"}, Resources: []string{"tokens"}}
	parent := h.mint(t, func(c *token.Claims) {
		c.Ancestors = nil
		for i := range ancestors {
			c.Ancestors = append(c.Ancestors, "tok_ANCESTOR"+strconv.Itoa(i))
		}
	}, issuer)

	return h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
		Token: parent, Sub: "app", Permissions: []*dnsgatev1.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}},
	})
}

func TestCreateTokenStopsAtTheMaximumChainDepth(t *testing.T) {
	h := newHarness(t)

	// The default maximum is eight ancestors.
	resp, err := h.issueAtDepth(t, 7)
	if err != nil {
		t.Fatalf("CreateToken at the last level: %v", err)
	}

	got, err := h.client.InspectToken(t.Context(), resp.GetToken())
	if err != nil {
		t.Fatal(err)
	}

	if len(got.GetAncestors()) != 8 {
		t.Errorf("ancestors = %d, want 8", len(got.GetAncestors()))
	}

	_, err = h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
		Token: resp.GetToken(), Sub: "app", Permissions: []*dnsgatev1.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}},
	})
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

	_, err = h.issueAtDepth(t, 8)
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)
}

func TestTheMaximumChainDepthIsConfigurable(t *testing.T) {
	h := newHarness(t)
	h.maxAncestors = 2
	h.serve(t, h.keys)

	if _, err := h.issueAtDepth(t, 1); err != nil {
		t.Fatalf("CreateToken below the maximum: %v", err)
	}

	_, err := h.issueAtDepth(t, 2)
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

	h.maxAncestors = 12
	h.serve(t, h.keys)

	if _, err := h.issueAtDepth(t, 11); err != nil {
		t.Fatalf("CreateToken beyond the default maximum: %v", err)
	}

	_, err = h.issueAtDepth(t, 12)
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)
}

func TestCreateTokenIsAuditedWithoutSecrets(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	rootClaims, err := h.client.InspectToken(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}

	resp := h.createToken(t, root, "external-dns-prod", appPermissions())

	_, deniedErr := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
		Token: resp.GetToken(), Sub: "app", Permissions: appPermissions(),
	})
	if deniedErr == nil {
		t.Fatal("a token without create on tokens issued one")
	}

	var created, denied []map[string]any

	for _, e := range h.auditEvents(t) {
		switch {
		case e["event"] != "token.create":
		case e["result"] == "ok":
			created = append(created, e)
		default:
			denied = append(denied, e)
		}
	}

	if len(created) != 1 || len(denied) != 1 {
		t.Fatalf("token.create events = %v, %v, want one ok and one denied", created, denied)
	}

	for field, want := range map[string]any{
		"time":            "2026-10-08T12:00:00Z",
		"jti":             resp.GetJti(),
		"parent_jti":      rootClaims.GetJti(),
		"service_account": "external-dns-prod",
		"provider":        "cloudflare",
		"verb":            "create",
	} {
		if created[0][field] != want {
			t.Errorf("audit %s = %v, want %v", field, created[0][field], want)
		}
	}

	if d := denied[0]; d["parent_jti"] != resp.GetJti() || d["category"] != "permission_denied" || d["jti"] != nil {
		t.Errorf("denied event = %v, want the parent's jti, permission_denied and no new jti", d)
	}

	for _, s := range []string{cfToken, bootstrapSecret, root, resp.GetToken()} {
		if strings.Contains(h.audit.String(), s) {
			t.Errorf("audit log contains a secret:\n%s", h.audit.String())
		}

		if strings.Contains(deniedErr.Error(), s) {
			t.Errorf("error %q contains a secret", deniedErr)
		}
	}
}

func TestCreateTokenReturnsNoTokenWhenItsAuditEventIsLost(t *testing.T) {
	h := newHarnessAuditingTo(t, failingWriter{})

	parent := h.mint(t, nil, token.Permission{Verbs: []string{"create", "get"}, Resources: []string{"tokens", "records"}})

	resp, err := h.client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
		Token: parent, Sub: "app", Permissions: []*dnsgatev1.Permission{{Verbs: []string{"get"}}},
	})
	wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

	if resp.GetToken() != "" {
		t.Error("a Derived Token was returned without its audit event")
	}
}

func TestCreateTokenRejectsMalformedRequests(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	for name, edit := range map[string]func(*dnsgatev1.CreateTokenRequest){
		"no sub":                func(r *dnsgatev1.CreateTokenRequest) { r.Sub = "" },
		"no permissions":        func(r *dnsgatev1.CreateTokenRequest) { r.Permissions = nil },
		"a rule without verbs":  func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Verbs = nil },
		"unknown verb":          func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Verbs = []string{"get", "write"} },
		"unknown resource":      func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Resources = []string{"accounts"} },
		"unknown egress":        func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Egress = []string{"direct"} },
		"empty zone":            func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Zones = []string{""} },
		"empty type":            func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Types = []string{""} },
		"empty name":            func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Names = []string{""} },
		"name with empty label": func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Names = []string{"www..apps"} },
		"apex in a name":        func(r *dnsgatev1.CreateTokenRequest) { r.Permissions[0].Names = []string{"www.@"} },
	} {
		t.Run(name, func(t *testing.T) {
			req := &dnsgatev1.CreateTokenRequest{Token: root, Sub: "app", Permissions: appPermissions()}
			edit(req)

			_, err := h.client.CreateToken(t.Context(), req)
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)
		})
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

	if got := resp.GetRecordSet().GetRecords(); len(got) != 2 {
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
