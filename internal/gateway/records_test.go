package gateway_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// addZones scripts the fake Provider with example.com, holding records of
// several names and types, and example.org.
func (h *harness) addZones() {
	h.fake.AddZone(dnsprovider.Zone{ID: "z-com", Name: "example.com", State: dnsprovider.HostingActive, Nameservers: []string{"ns1.cf", "ns2.cf"}},
		dnsprovider.Record{ID: "r1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300},
		dnsprovider.Record{ID: "r2", Type: "A", Name: "www.apps.example.com", Value: "192.0.2.10", TTL: 300},
		dnsprovider.Record{ID: "r3", Type: "A", Name: "www.apps.example.com", Value: "192.0.2.11", TTL: 120},
		dnsprovider.Record{ID: "r4", Type: "TXT", Name: "www.apps.example.com", Value: `"v=1"`, TTL: 300},
		dnsprovider.Record{ID: "r5", Type: "A", Name: "apps.example.com", Value: "192.0.2.20", TTL: 300},
		dnsprovider.Record{ID: "r6", Type: "TXT", Name: "_acme-challenge.www.example.com", Value: `"abc"`, TTL: 60},
	)
	h.fake.AddZone(dnsprovider.Zone{ID: "z-org", Name: "example.org", State: dnsprovider.HostingPending},
		dnsprovider.Record{ID: "r7", Type: "A", Name: "example.org", Value: "198.51.100.1", TTL: 300},
	)
}

// providerCalls returns the operations the fake Provider was called with,
// in order.
func (h *harness) providerCalls() []providertest.Op {
	var ops []providertest.Op

	for _, c := range h.fake.Calls() {
		ops = append(ops, c.Op)
	}

	return ops
}

// mint seals a Service Token for the Service Account "app" with the
// Gateway's keys, the Provider Credential cfToken and perms, edited by
// edit if given. It stands in for issuing a Derived Token.
func (h *harness) mint(t *testing.T, edit func(*token.Claims), perms ...token.Permission) string {
	t.Helper()

	return h.mintAs(t, token.Issuer, token.Audience, edit, perms...)
}

// mintAs is mint with the iss and aud claims as given, for tokens the
// Gateway never mints.
func (h *harness) mintAs(t *testing.T, iss, aud string, edit func(*token.Claims), perms ...token.Permission) string {
	t.Helper()

	claims := token.Claims{
		Subject:     "app",
		ID:          "tok_01TESTAPP",
		IssuedAt:    token.NewNumericDate(h.now),
		NotBefore:   token.NewNumericDate(h.now),
		Ancestors:   []string{"tok_01TESTROOT"},
		Provider:    "cloudflare",
		Credential:  token.Credential{Type: "api-token", Value: token.NewSecret(cfToken)},
		Permissions: perms,
	}

	if edit != nil {
		edit(&claims)
	}

	sealed, err := token.NewCodec(h.keys, token.WithClock(func() time.Time { return h.now })).SealAs(t.Context(), claims, iss, aud)
	if err != nil {
		t.Fatal(err)
	}

	return sealed
}

func zoneNames(zones []*dnsgatev1.Zone) []string {
	var names []string

	for _, z := range zones {
		names = append(names, z.GetName())
	}

	return names
}

func TestListZonesWithRootToken(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root})
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}

	if got := zoneNames(resp.GetZones()); !slices.Equal(got, []string{"example.com", "example.org"}) {
		t.Errorf("zones = %v, want example.com and example.org", got)
	}

	com := resp.GetZones()[0]
	if com.GetState() != dnsgatev1.Zone_STATE_ACTIVE || !slices.Equal(com.GetNameservers(), []string{"ns1.cf", "ns2.cf"}) {
		t.Errorf("example.com = %v, want active with its nameservers", com)
	}

	if org := resp.GetZones()[1]; org.GetState() != dnsgatev1.Zone_STATE_PENDING {
		t.Errorf("example.org state = %v, want pending", org.GetState())
	}

	// The Provider was built from the token's Provider Credential.
	calls := h.fake.Calls()
	if len(calls) == 0 || calls[0].Op != providertest.OpNew || calls[0].Fields["token"] != cfToken {
		t.Errorf("provider calls = %+v, want it built from the Provider Credential first", calls)
	}
}

func TestGetZoneWithRootToken(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.GetZone(t.Context(), &dnsgatev1.GetZoneRequest{Token: root, Zone: "Example.COM."})
	if err != nil {
		t.Fatalf("GetZone: %v", err)
	}

	if z := resp.GetZone(); z.GetName() != "example.com" || z.GetState() != dnsgatev1.Zone_STATE_ACTIVE {
		t.Errorf("zone = %v, want example.com, active", z)
	}
}

// recordSets formats RRsets as "name type ttl value,value" lines.
func recordSets(sets []*dnsgatev1.RecordSet) []string {
	var out []string

	for _, s := range sets {
		out = append(out, fmt.Sprintf("%s %s %d %s", s.GetName(), s.GetType(), s.GetTtl(), strings.Join(s.GetValues(), ",")))
	}

	return out
}

func TestListRecordsWithRootTokenReturnsRRsets(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: root, Zone: "example.com"})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	// Sorted by name and type, names relative to the zone, each RRset
	// with its records' lowest TTL.
	want := []string{
		"@ A 300 192.0.2.1",
		"_acme-challenge.www TXT 60 \"abc\"",
		"apps A 300 192.0.2.20",
		"www.apps A 120 192.0.2.10,192.0.2.11",
		"www.apps TXT 300 \"v=1\"",
	}

	if got := recordSets(resp.GetRecordSets()); !slices.Equal(got, want) {
		t.Errorf("record sets =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestGetRecordWithRootToken(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	for _, tc := range []struct {
		name, typ string
		want      string
	}{
		{"www.apps", "A", "www.apps A 120 192.0.2.10,192.0.2.11"},
		{"WWW.Apps", "a", "www.apps A 120 192.0.2.10,192.0.2.11"},
		{"@", "A", "@ A 300 192.0.2.1"},
		{"apps", "A", "apps A 300 192.0.2.20"},
	} {
		resp, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: root, Zone: "example.com", Name: tc.name, Type: tc.typ})
		if err != nil {
			t.Errorf("GetRecord %s %s: %v", tc.name, tc.typ, err)

			continue
		}

		if got := recordSets([]*dnsgatev1.RecordSet{resp.GetRecordSet()}); got[0] != tc.want {
			t.Errorf("GetRecord %s %s = %q, want %q", tc.name, tc.typ, got[0], tc.want)
		}
	}
}

func TestGetRecordOfAnRRsetTheZoneLacksIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	_, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: root, Zone: "example.com", Name: "www.apps", Type: "AAAA"})
	wantError(t, err, codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND)
}

func TestListsShowOnlyWhatALimitedTokenCovers(t *testing.T) {
	read := []string{"get", "list"}

	for name, tc := range map[string]struct {
		perm    token.Permission
		zones   []string
		records []string
	}{
		"limited by zone": {
			perm:    token.Permission{Verbs: read, Resources: []string{"zones", "records"}, Zones: []string{"example.com"}},
			zones:   []string{"example.com"},
			records: []string{"@ A", "_acme-challenge.www TXT", "apps A", "www.apps A", "www.apps TXT"},
		},
		"limited by name": {
			perm:    token.Permission{Verbs: read, Resources: []string{"zones", "records"}, Names: []string{"*.apps"}},
			zones:   []string{"example.com", "example.org"},
			records: []string{"www.apps A", "www.apps TXT"},
		},
		"limited by type": {
			perm:    token.Permission{Verbs: read, Resources: []string{"zones", "records"}, Types: []string{"TXT"}},
			zones:   []string{"example.com", "example.org"},
			records: []string{"_acme-challenge.www TXT", "www.apps TXT"},
		},
		"limited by name and type": {
			perm:    token.Permission{Verbs: read, Resources: []string{"zones", "records"}, Names: []string{"@", "**.apps"}, Types: []string{"A"}},
			zones:   []string{"example.com", "example.org"},
			records: []string{"@ A", "www.apps A"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.addZones()

			tok := h.mint(t, nil, tc.perm)

			zones, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: tok})
			if err != nil {
				t.Fatalf("ListZones: %v", err)
			}

			if got := zoneNames(zones.GetZones()); !slices.Equal(got, tc.zones) {
				t.Errorf("zones = %v, want %v", got, tc.zones)
			}

			records, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: tok, Zone: "example.com"})
			if err != nil {
				t.Fatalf("ListRecords: %v", err)
			}

			var got []string
			for _, s := range records.GetRecordSets() {
				got = append(got, s.GetName()+" "+s.GetType())
			}

			if !slices.Equal(got, tc.records) {
				t.Errorf("record sets = %v, want %v", got, tc.records)
			}
		})
	}
}

func TestNamePatternsOfRecordCalls(t *testing.T) {
	for _, tc := range []struct {
		pattern, name, typ string
		allowed            bool
	}{
		{"@", "@", "A", true},
		{"@", "apps", "A", false},
		{"*", "apps", "A", true},
		{"*", "www.apps", "A", false},
		{"*", "@", "A", false},
		{"**", "apps", "A", true},
		{"**", "www.apps", "A", true},
		{"**", "_acme-challenge.www", "TXT", true},
		{"**", "@", "A", false},
		{"*.apps", "www.apps", "A", true},
		{"*.apps", "apps", "A", false},
		{"**.apps", "www.apps", "TXT", true},
		{"**.apps", "apps", "A", false},
	} {
		t.Run(tc.pattern+" "+tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.addZones()

			tok := h.mint(t, nil, token.Permission{Verbs: []string{"get"}, Names: []string{tc.pattern}})

			err := h.call(t, tok, &dnsgatev1.GetRecordRequest{Zone: "example.com", Name: tc.name, Type: tc.typ})
			if tc.allowed {
				if err != nil {
					t.Errorf("GetRecord %s under %q: %v, want it allowed", tc.name, tc.pattern, err)
				}

				return
			}

			wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

			if calls := h.fake.Calls(); len(calls) != 0 {
				t.Errorf("provider calls = %+v, want none", calls)
			}
		})
	}
}

func TestRequestsOutsideThePermissionsAreDeniedBeforeTheProvider(t *testing.T) {
	limited := token.Permission{
		Verbs:     []string{"get"},
		Resources: []string{"records"},
		Zones:     []string{"example.com"},
		Names:     []string{"*.apps"},
		Types:     []string{"A"},
		Egress:    []string{"gateway"},
	}

	for name, tc := range map[string]struct {
		perm token.Permission
		req  any
	}{
		"wrong verb": {limited, &dnsgatev1.ListRecordsRequest{Zone: "example.com"}},
		"wrong zone": {limited, &dnsgatev1.GetRecordRequest{Zone: "example.org", Name: "www.apps", Type: "A"}},
		"wrong name": {limited, &dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "apps", Type: "A"}},
		"wrong type": {limited, &dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "www.apps", Type: "TXT"}},
		"wrong egress": {
			token.Permission{Verbs: []string{"get"}, Egress: []string{"agent"}},
			&dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "www.apps", Type: "A", Egress: dnsgatev1.Egress_EGRESS_GATEWAY},
		},
		"zones not granted": {
			token.Permission{Verbs: []string{"get", "list"}},
			&dnsgatev1.ListZonesRequest{},
		},
		"zone not granted": {
			token.Permission{Verbs: []string{"get"}, Resources: []string{"zones"}, Zones: []string{"example.org"}},
			&dnsgatev1.GetZoneRequest{Zone: "example.com"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.addZones()

			err := h.call(t, h.mint(t, nil, tc.perm), tc.req)
			wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

			if calls := h.fake.Calls(); len(calls) != 0 {
				t.Errorf("provider calls = %+v, want none", calls)
			}
		})
	}
}

// call sends req, a zone or record request, presenting tok.
func (h *harness) call(t *testing.T, tok string, req any) error {
	t.Helper()

	var err error

	switch req := req.(type) {
	case *dnsgatev1.ListZonesRequest:
		req.Token = tok
		_, err = h.client.ListZones(t.Context(), req)
	case *dnsgatev1.GetZoneRequest:
		req.Token = tok
		_, err = h.client.GetZone(t.Context(), req)
	case *dnsgatev1.ListRecordsRequest:
		req.Token = tok
		_, err = h.client.ListRecords(t.Context(), req)
	case *dnsgatev1.GetRecordRequest:
		req.Token = tok
		_, err = h.client.GetRecord(t.Context(), req)
	default:
		t.Fatalf("unknown request %T", req)
	}

	return err
}

func TestInvalidTokensAreRejectedBeforeTheProvider(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	full := token.Permission{Verbs: []string{"get", "list"}, Resources: []string{"zones", "records"}}

	expiring := h.mint(t, func(c *token.Claims) {
		exp := token.NewNumericDate(h.now.Add(time.Minute))
		c.Expiry = &exp
	}, full)
	notYetValid := h.mint(t, func(c *token.Claims) { c.NotBefore = token.NewNumericDate(h.now.Add(time.Hour)) }, full)
	wrongIssuer := h.mintAs(t, "another-gateway", token.Audience, nil, full)
	wrongAudience := h.mintAs(t, token.Issuer, "another-service", nil, full)

	// A token of another Gateway: same kids, different keys.
	other := newHarness(t)
	foreign := other.mint(t, nil, full)

	good := h.mint(t, nil, full)
	parts := strings.Split(good, ".")
	parts[3] = strings.Repeat("A", len(parts[3]))
	tampered := strings.Join(parts, ".")

	h.now = h.now.Add(time.Minute)

	for name, tok := range map[string]string{
		"empty":          "",
		"garbage":        "not-a-token",
		"tampered":       tampered,
		"foreign":        foreign,
		"expired":        expiring,
		"not yet valid":  notYetValid,
		"wrong issuer":   wrongIssuer,
		"wrong audience": wrongAudience,
	} {
		t.Run(name, func(t *testing.T) {
			for _, req := range []any{
				&dnsgatev1.ListZonesRequest{},
				&dnsgatev1.GetZoneRequest{Zone: "example.com"},
				&dnsgatev1.ListRecordsRequest{Zone: "example.com"},
				&dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "www.apps", Type: "A"},
			} {
				err := h.call(t, tok, req)
				wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
			}
		})
	}

	if calls := h.fake.Calls(); len(calls) != 0 {
		t.Errorf("provider calls = %+v, want none", calls)
	}

	if _, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: good}); err != nil {
		t.Errorf("the untampered token: %v", err)
	}
}

func TestEgressSelection(t *testing.T) {
	read := []string{"get", "list"}

	for name, tc := range map[string]struct {
		egress    []string
		requested dnsgatev1.Egress
		code      codes.Code
		category  dnsgatev1.Error_Category
	}{
		"none asked, both allowed":  {nil, dnsgatev1.Egress_EGRESS_UNSPECIFIED, codes.OK, 0},
		"gateway asked and allowed": {[]string{"gateway"}, dnsgatev1.Egress_EGRESS_GATEWAY, codes.OK, 0},
		"agent asked, both allowed": {
			nil, dnsgatev1.Egress_EGRESS_AGENT, codes.Unimplemented, dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED,
		},
		"agent asked and allowed": {
			[]string{"agent"}, dnsgatev1.Egress_EGRESS_AGENT, codes.Unimplemented, dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED,
		},
		"agent asked, gateway only": {
			[]string{"gateway"}, dnsgatev1.Egress_EGRESS_AGENT, codes.Unimplemented, dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED,
		},
		"none asked, agent only": {
			[]string{"agent"}, dnsgatev1.Egress_EGRESS_UNSPECIFIED, codes.Unimplemented, dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED,
		},
		"gateway asked, agent only": {
			[]string{"agent"}, dnsgatev1.Egress_EGRESS_GATEWAY, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"unknown egress": {
			nil, dnsgatev1.Egress(42), codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.addZones()

			tok := h.mint(t, nil, token.Permission{Verbs: read, Egress: tc.egress})

			_, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: tok, Zone: "example.com", Egress: tc.requested})

			if tc.code == codes.OK {
				if err != nil {
					t.Fatalf("ListRecords: %v", err)
				}

				if e := h.auditEvents(t); len(e) != 0 {
					t.Errorf("audit events = %v, want none for an allowed read", e)
				}

				return
			}

			wantError(t, err, tc.code, tc.category)

			if calls := h.fake.Calls(); len(calls) != 0 {
				t.Errorf("provider calls = %+v, want none", calls)
			}

			if tc.category == dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED && !strings.Contains(err.Error(), "not supported yet") {
				t.Errorf("error = %v, want it to say agent egress is not supported yet", err)
			}
		})
	}
}

// rawProviderMessage is in every scripted Provider error answer; it must
// never reach the client or the audit log.
const rawProviderMessage = "cloudflare says: request for zone 023e105f4ecef8ad9ca31a8372d0c353 failed"

func TestProviderErrorsReachTheClientAsCategories(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		code     codes.Code
		category dnsgatev1.Error_Category
		status   int32
	}{
		"403": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 403},
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, 403,
		},
		"401": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 401},
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, 401,
		},
		"bad token answered with 400": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 400, Kind: dnsprovider.ErrUnauthorized},
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, 400,
		},
		"404": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 404},
			codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND, 404,
		},
		"429": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 429, RetryAfter: time.Minute},
			codes.ResourceExhausted, dnsgatev1.Error_CATEGORY_RATE_LIMITED, 429,
		},
		"400": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 400},
			codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD, 400,
		},
		"500": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 500},
			codes.Unavailable, dnsgatev1.Error_CATEGORY_INTERNAL, 500,
		},
		"zone unknown to the provider": {
			fmt.Errorf("zone %q: %w", rawProviderMessage, dnsprovider.ErrNotFound),
			codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND, 0,
		},
		"connection lost": {
			fmt.Errorf("%s: %w", rawProviderMessage, errors.New("connection reset")),
			codes.Unavailable, dnsgatev1.Error_CATEGORY_INTERNAL, 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.addZones()

			if apiErr, ok := tc.err.(*dnsprovider.APIError); ok {
				apiErr.Messages = []string{rawProviderMessage + " (code 10000)"}
			}

			h.fake.Fail(providertest.OpZone, tc.err)

			root := h.onboard(t, onboardRequest())

			for _, req := range []any{
				&dnsgatev1.GetZoneRequest{Zone: "example.com"},
				&dnsgatev1.ListRecordsRequest{Zone: "example.com"},
				&dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "www.apps", Type: "A"},
			} {
				err := h.call(t, root, req)
				wantError(t, err, tc.code, tc.category)

				st := status.Convert(err)
				if got := dnsgatev1.ErrorDetail(st).GetProviderStatus(); got != tc.status {
					t.Errorf("provider status = %d, want %d", got, tc.status)
				}

				if strings.Contains(err.Error(), "cloudflare says") || strings.Contains(fmt.Sprint(st.Proto()), "cloudflare says") {
					t.Errorf("error %v carries the raw Provider answer", err)
				}
			}

			// The audit fields are an allowlist, which leaves out the
			// Provider's own messages.
			if strings.Contains(h.audit.String(), "cloudflare says") {
				t.Errorf("audit log carries the raw Provider answer:\n%s", h.audit.String())
			}

			for _, e := range h.auditEvents(t)[1:] {
				if e["result"] != "failed" || e["category"] != tc.category.Name() {
					t.Errorf("audit event = %v, want a failed one, category %s", e, tc.category.Name())
				}

				if tc.status != 0 && e["provider_status"] != float64(tc.status) {
					t.Errorf("audit provider_status = %v, want %d", e["provider_status"], tc.status)
				}
			}
		})
	}
}

func TestAProviderThatCannotBeBuiltIsLoggedWithoutItsError(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	// A Provider's build error may quote what it was built from.
	h.fake.Fail(providertest.OpNew, fmt.Errorf("%s: credential %q rejected", rawProviderMessage, cfToken))

	root := h.onboard(t, onboardRequest())

	_, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root})
	wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

	logs := h.logs.String()
	if !strings.Contains(logs, "building provider") || !strings.Contains(logs, "reason=provider_rejected_credential") {
		t.Errorf("logs =\n%s\nwant the failed build and its reason", logs)
	}

	for _, leak := range []string{cfToken, "cloudflare says"} {
		if strings.Contains(logs, leak) || strings.Contains(h.audit.String(), leak) || strings.Contains(err.Error(), leak) {
			t.Errorf("%q leaked:\nlogs:\n%s\naudit:\n%s\nerror: %v", leak, logs, h.audit.String(), err)
		}
	}
}

func TestDenialsAreAuditedWithoutSecrets(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	tok := h.mint(t, nil, token.Permission{
		Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"*.apps"}, Types: []string{"A"},
	})

	var errs []error

	for _, req := range []any{
		&dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "_acme-challenge", Type: "TXT"},
		&dnsgatev1.GetRecordRequest{Zone: "example.com", Name: "www.apps", Type: "A", Egress: dnsgatev1.Egress_EGRESS_AGENT},
		&dnsgatev1.ListZonesRequest{},
	} {
		errs = append(errs, h.call(t, tok, req))
	}

	errs = append(errs, h.call(t, tok+"x", &dnsgatev1.ListRecordsRequest{Zone: "example.com"}))
	errs = append(errs, h.call(t, tok, &dnsgatev1.GetRecordRequest{Zone: "example.com", Name: cfToken + ".", Type: "A"}))

	events := h.auditEvents(t)
	if len(events) != len(errs) {
		t.Fatalf("audit events = %v, want %d", events, len(errs))
	}

	want := []map[string]any{
		{
			"event": "records.get", "result": "denied", "category": "permission_denied",
			"service_account": "app", "jti": "tok_01TESTAPP", "provider": "cloudflare",
			"zone": "example.com", "record_name": "_acme-challenge", "record_type": "TXT", "verb": "get",
		},
		{
			"event": "records.get", "result": "denied", "category": "egress_not_supported",
			"service_account": "app", "requested_egress": "agent", "record_name": "www.apps",
		},
		{"event": "zones.list", "result": "denied", "category": "permission_denied", "verb": "list"},
		{"event": "records.list", "result": "denied", "category": "unauthenticated", "service_account": nil},
		{"event": "records.get", "result": "denied", "category": "invalid_request", "record_name": nil},
	}

	for i, fields := range want {
		for field, v := range fields {
			if events[i][field] != v {
				t.Errorf("audit event %d %s = %v, want %v", i, field, events[i][field], v)
			}
		}

		if id, _ := events[i]["request_id"].(string); !strings.HasPrefix(id, "req_") {
			t.Errorf("audit event %d request_id = %v, want a req_ prefix", i, events[i]["request_id"])
		}
	}

	for _, secret := range []string{cfToken, tok} {
		if strings.Contains(h.audit.String(), secret) {
			t.Errorf("audit log contains a secret:\n%s", h.audit.String())
		}

		for _, err := range errs {
			if err == nil {
				t.Fatal("a denied request succeeded")
			}

			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q contains a secret", err)
			}
		}
	}

	if calls := h.fake.Calls(); len(calls) != 0 {
		t.Errorf("provider calls = %+v, want none", calls)
	}
}

func TestEgressNotSupportedIsAudited(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	tok := h.mint(t, nil, token.Permission{Verbs: []string{"list"}, Egress: []string{"agent"}})

	_, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: tok, Zone: "example.com"})
	wantError(t, err, codes.Unimplemented, dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED)

	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit events = %v, want one", events)
	}

	e := events[0]
	if e["event"] != "records.list" || e["result"] != "denied" || e["category"] != "egress_not_supported" ||
		e["requested_egress"] != nil || e["egress"] != nil {
		t.Errorf("audit event = %v, want a denied records.list, egress not supported, no egress", e)
	}
}
