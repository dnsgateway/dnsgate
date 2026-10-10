package gateway_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dnsgateway/dnsgate/internal/token"
)

// newMutationHarness returns a harness whose fake Provider holds
// addZones' zones and takes each Changeset whole, as a Batcher, so the
// test sees the Changesets the Gateway applies.
func newMutationHarness(t *testing.T) *harness {
	t.Helper()

	h := newHarness(t)
	h.addZones()
	h.fake.SetBatcher(true)

	return h
}

// changesets formats the changes of each Changeset the fake Provider
// applied, one line per change: "add TYPE NAME VALUE TTL", "delete TYPE
// NAME VALUE TTL" or "modify TYPE NAME VALUE TTL -> VALUE TTL", each
// VALUE followed by its Record Extras, if any, as formatExtras does.
func (h *harness) changesets() [][]string {
	var out [][]string

	for _, c := range h.fake.Calls() {
		if c.Op != providertest.OpApply {
			continue
		}

		var lines []string

		for _, ch := range c.Changeset.Changes {
			lines = append(lines, formatChange(ch))
		}

		out = append(out, lines)
	}

	return out
}

func formatChange(c dnsprovider.Change) string {
	rec := func(r dnsprovider.Record) string {
		return fmt.Sprintf("%s %s %s%s %d", r.Type, r.Name, r.Value, formatExtras(r.Extras), r.TTL)
	}

	switch c.Kind {
	case dnsprovider.ChangeAdd:
		return "add " + rec(c.After)
	case dnsprovider.ChangeModify:
		return fmt.Sprintf("modify %s -> %s%s %d", rec(c.Before), c.After.Value, formatExtras(c.After.Extras), c.After.TTL)
	case dnsprovider.ChangeDelete:
		return "delete " + rec(c.Before)
	}

	return fmt.Sprintf("unknown %+v", c)
}

// wantChangesets checks that the fake Provider applied exactly want, each
// Changeset's changes in any order.
func wantChangesets(t *testing.T, h *harness, want ...[]string) {
	t.Helper()

	got := h.changesets()
	for _, cs := range got {
		slices.Sort(cs)
	}

	for _, cs := range want {
		slices.Sort(cs)
	}

	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("changesets =\n%s\nwant\n%s", formatChangesets(got), formatChangesets(want))
	}
}

func formatChangesets(css [][]string) string {
	var b strings.Builder

	for i, cs := range css {
		fmt.Fprintf(&b, "changeset %d:\n  %s\n", i, strings.Join(cs, "\n  "))
	}

	return b.String()
}

// getRecordSet reads one RRset with tok, formatted as recordSets does; ""
// when the zone does not hold it.
func (h *harness) getRecordSet(t *testing.T, tok, name, typ string) string {
	t.Helper()

	resp, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: tok, Zone: "example.com", Name: name, Type: typ})
	if err != nil {
		return ""
	}

	return recordSets([]*dnsgatev1.RecordSet{resp.GetRecordSet()})[0]
}

func TestCreateRecordCreatesAnRRset(t *testing.T) {
	h := newMutationHarness(t)

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Zone: "example.com", Name: "API", Type: "a", Ttl: 600, Records: values("192.0.2.30", "192.0.2.31"),
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	want := "api A 600 192.0.2.30,192.0.2.31"
	if got := recordSets([]*dnsgatev1.RecordSet{resp.GetRecordSet()}); got[0] != want {
		t.Errorf("created RRset = %q, want %q", got[0], want)
	}

	wantChangesets(t, h, []string{
		"add A api.example.com 192.0.2.30 600",
		"add A api.example.com 192.0.2.31 600",
	})

	if got := h.getRecordSet(t, root, "api", "A"); got != want {
		t.Errorf("RRset read back = %q, want %q", got, want)
	}
}

func TestCreateRecordOfAnRRsetTheZoneHoldsIsAConflict(t *testing.T) {
	h := newMutationHarness(t)

	root := h.onboard(t, onboardRequest())

	_, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Zone: "example.com", Name: "www.apps", Type: "A", Ttl: 300, Records: values("192.0.2.99"),
	})
	wantError(t, err, codes.AlreadyExists, dnsgatev1.Error_CATEGORY_CONFLICT)

	wantChangesets(t, h)

	if got, want := h.getRecordSet(t, root, "www.apps", "A"), "www.apps A 120 192.0.2.10,192.0.2.11"; got != want {
		t.Errorf("RRset = %q, want it untouched: %q", got, want)
	}
}

func TestMalformedRecordsAreRefusedBeforeTheProvider(t *testing.T) {
	for name, tc := range map[string]struct {
		typ      string
		ttl      uint32
		values   []string
		code     codes.Code
		category dnsgatev1.Error_Category
	}{
		"no values":         {"A", 300, nil, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST},
		"value given twice": {"A", 300, []string{"192.0.2.1", "192.0.2.1"}, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST},
		"value of another type": {
			"A", 300, []string{"2001:db8::1"}, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD,
		},
		"empty value":       {"TXT", 300, []string{""}, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD},
		"TTL out of range":  {"A", 5, []string{"192.0.2.1"}, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD},
		"no TTL":            {"A", 0, []string{"192.0.2.1"}, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD},
		"type not editable": {"SOA", 300, []string{"ns1 hostmaster 1 2 3 4 5"}, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD},
	} {
		t.Run(name, func(t *testing.T) {
			h := newMutationHarness(t)

			root := h.onboard(t, onboardRequest())

			_, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
				Token: root, Zone: "example.com", Name: "api", Type: tc.typ, Ttl: tc.ttl, Records: values(tc.values...),
			})
			wantError(t, err, tc.code, tc.category)

			if ops := h.providerCalls(); slices.ContainsFunc(ops, func(op providertest.Op) bool { return op != providertest.OpNew }) {
				t.Errorf("provider calls = %v, want none past building it", ops)
			}

			events := h.auditEvents(t)[1:]
			if len(events) != 1 || events[0]["event"] != "records.create" || events[0]["result"] != "failed" || events[0]["category"] != tc.category.Name() {
				t.Errorf("audit events = %v, want one failed records.create, category %s", events, tc.category.Name())
			}
		})
	}
}

// sortedSet formats an RRset as recordSets does, its values sorted.
func sortedSet(s *dnsgatev1.RecordSet) string {
	var vs []string
	for _, r := range s.GetRecords() {
		vs = append(vs, formatValue(r))
	}

	slices.Sort(vs)

	return fmt.Sprintf("%s %s %d %s", s.GetName(), s.GetType(), s.GetTtl(), strings.Join(vs, ","))
}

// readSet reads one RRset of example.com with tok, formatted by
// sortedSet; "" when the zone does not hold it.
func (h *harness) readSet(t *testing.T, tok, name, typ string) string {
	t.Helper()

	resp, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: tok, Zone: "example.com", Name: name, Type: typ})
	if status.Code(err) == codes.NotFound {
		return ""
	}

	if err != nil {
		t.Fatalf("GetRecord %s %s: %v", name, typ, err)
	}

	return sortedSet(resp.GetRecordSet())
}

func TestUpdateRecordReplacesEveryValueOfTheRRset(t *testing.T) {
	for name, tc := range map[string]struct {
		ttl     uint32
		values  []string
		changes []string
		want    string
	}{
		"more values": {
			300,
			[]string{"192.0.2.11", "192.0.2.12", "192.0.2.13"},
			[]string{
				"modify A www.apps.example.com 192.0.2.11 120 -> 192.0.2.11 300",
				"modify A www.apps.example.com 192.0.2.10 300 -> 192.0.2.12 300",
				"add A www.apps.example.com 192.0.2.13 300",
			},
			"www.apps A 300 192.0.2.11,192.0.2.12,192.0.2.13",
		},
		"fewer values": {
			300,
			[]string{"192.0.2.10"},
			[]string{"delete A www.apps.example.com 192.0.2.11 120"},
			"www.apps A 300 192.0.2.10",
		},
		"other values": {
			60,
			[]string{"192.0.2.50"},
			[]string{
				"modify A www.apps.example.com 192.0.2.10 300 -> 192.0.2.50 60",
				"delete A www.apps.example.com 192.0.2.11 120",
			},
			"www.apps A 60 192.0.2.50",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newMutationHarness(t)

			root := h.onboard(t, onboardRequest())

			resp, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
				Token: root, Zone: "example.com", Name: "www.apps", Type: "A", Ttl: tc.ttl, Records: values(tc.values...),
			})
			if err != nil {
				t.Fatalf("UpdateRecord: %v", err)
			}

			if got := sortedSet(resp.GetRecordSet()); got != tc.want {
				t.Errorf("updated RRset = %q, want %q", got, tc.want)
			}

			wantChangesets(t, h, tc.changes)

			if got := h.readSet(t, root, "www.apps", "A"); got != tc.want {
				t.Errorf("RRset read back = %q, want %q", got, tc.want)
			}

			// The RRset of the same name and another type is left alone.
			if got, want := h.readSet(t, root, "www.apps", "TXT"), `www.apps TXT 300 "v=1"`; got != want {
				t.Errorf("TXT RRset = %q, want %q", got, want)
			}
		})
	}
}

func TestUpdateRecordWithTheValuesTheRRsetHoldsChangesNothing(t *testing.T) {
	h := newMutationHarness(t)

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "@", Type: "A", Ttl: 300, Records: values("192.0.2.1"),
	})
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	if got, want := sortedSet(resp.GetRecordSet()), "@ A 300 192.0.2.1"; got != want {
		t.Errorf("RRset = %q, want %q", got, want)
	}

	wantChangesets(t, h)
}

func TestPatchRecordAddsAndRemovesSingleValues(t *testing.T) {
	const acme = "_acme-challenge.www.example.com"

	for name, tc := range map[string]struct {
		req     *dnsgatev1.PatchRecordRequest
		changes []string
		// want is the RRset after, as sortedSet formats it; "" when the
		// zone no longer holds it.
		want string
	}{
		"add a value with the RRset's TTL": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Add: values(`"def"`)},
			[]string{`add TXT ` + acme + ` "def" 60`},
			`_acme-challenge.www TXT 60 "abc","def"`,
		},
		"add a value with its own TTL": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Ttl: 120, Add: values(`"def"`)},
			[]string{`add TXT ` + acme + ` "def" 120`},
			`_acme-challenge.www TXT 60 "abc","def"`,
		},
		"remove one value of two": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Remove: []string{"192.0.2.10"}},
			[]string{"delete A www.apps.example.com 192.0.2.10 300"},
			"www.apps A 120 192.0.2.11",
		},
		"add one value and remove another": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Add: values(`"def"`), Remove: []string{`"abc"`}},
			[]string{`modify TXT ` + acme + ` "abc" 60 -> "def" 60`},
			`_acme-challenge.www TXT 60 "def"`,
		},
		"add a value held and remove one not held": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: values("192.0.2.10"), Remove: []string{"192.0.2.99"}},
			nil,
			"www.apps A 120 192.0.2.10,192.0.2.11",
		},
		"add to an RRset the zone lacks": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.api", Type: "TXT", Ttl: 120, Add: values(`"xyz"`)},
			[]string{`add TXT _acme-challenge.api.example.com "xyz" 120`},
			`_acme-challenge.api TXT 120 "xyz"`,
		},
		"remove the last value": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Remove: []string{`"abc"`}},
			[]string{`delete TXT ` + acme + ` "abc" 60`},
			"",
		},
		"remove from an RRset the zone lacks": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.api", Type: "TXT", Remove: []string{`"xyz"`}},
			nil,
			"",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newMutationHarness(t)

			root := h.onboard(t, onboardRequest())

			req := tc.req
			req.Token, req.Zone = root, "example.com"

			resp, err := h.client.PatchRecord(t.Context(), req)
			if err != nil {
				t.Fatalf("PatchRecord: %v", err)
			}

			got := ""
			if resp.GetRecordSet() != nil {
				got = sortedSet(resp.GetRecordSet())
			}

			if got != tc.want {
				t.Errorf("patched RRset = %q, want %q", got, tc.want)
			}

			if tc.changes == nil {
				wantChangesets(t, h)
			} else {
				wantChangesets(t, h, tc.changes)
			}

			if got := h.readSet(t, root, req.GetName(), req.GetType()); got != tc.want {
				t.Errorf("RRset read back = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMalformedPatchesAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		req      *dnsgatev1.PatchRecordRequest
		category dnsgatev1.Error_Category
	}{
		"nothing to add or remove": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A"},
			dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
		"value added and removed": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: values("192.0.2.10"), Remove: []string{"192.0.2.10"}},
			dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
		"value added twice": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: values("192.0.2.12", "192.0.2.12")},
			dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
		"malformed value": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: values("www")},
			dnsgatev1.Error_CATEGORY_INVALID_RECORD,
		},
		"TTL out of range": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Ttl: 5, Add: values("192.0.2.12")},
			dnsgatev1.Error_CATEGORY_INVALID_RECORD,
		},
		"no TTL for a new RRset": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.api", Type: "TXT", Add: values(`"xyz"`)},
			dnsgatev1.Error_CATEGORY_INVALID_RECORD,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newMutationHarness(t)

			req := tc.req
			req.Token, req.Zone = h.onboard(t, onboardRequest()), "example.com"

			_, err := h.client.PatchRecord(t.Context(), req)
			wantError(t, err, codes.InvalidArgument, tc.category)

			wantChangesets(t, h)

			events := h.auditEvents(t)[1:]
			if len(events) != 1 || events[0]["event"] != "records.patch" || events[0]["result"] != "failed" || events[0]["category"] != tc.category.Name() {
				t.Errorf("audit events = %v, want one failed records.patch, category %s", events, tc.category.Name())
			}
		})
	}
}

func TestDeleteRecordDeletesEveryValueOfTheRRset(t *testing.T) {
	h := newMutationHarness(t)

	root := h.onboard(t, onboardRequest())

	if _, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
		Token: root, Zone: "example.com", Name: "www.apps", Type: "A",
	}); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	wantChangesets(t, h, []string{
		"delete A www.apps.example.com 192.0.2.10 300",
		"delete A www.apps.example.com 192.0.2.11 120",
	})

	if got := h.readSet(t, root, "www.apps", "A"); got != "" {
		t.Errorf("RRset read back = %q, want it gone", got)
	}

	if got, want := h.readSet(t, root, "www.apps", "TXT"), `www.apps TXT 300 "v=1"`; got != want {
		t.Errorf("TXT RRset = %q, want %q", got, want)
	}

	_, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
		Token: root, Zone: "example.com", Name: "www.apps", Type: "A",
	})
	wantError(t, err, codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND)
}

// mutations returns one request of each record verb on name and type of
// example.com, through egress.
func mutations(name, typ string, egress dnsgatev1.Egress) map[string]any {
	return map[string]any{
		"create": &dnsgatev1.CreateRecordRequest{Zone: "example.com", Name: name, Type: typ, Egress: egress, Ttl: 300, Records: values(`"v"`)},
		"update": &dnsgatev1.UpdateRecordRequest{Zone: "example.com", Name: name, Type: typ, Egress: egress, Ttl: 300, Records: values(`"v"`)},
		"patch":  &dnsgatev1.PatchRecordRequest{Zone: "example.com", Name: name, Type: typ, Egress: egress, Add: values(`"v"`)},
		"delete": &dnsgatev1.DeleteRecordRequest{Zone: "example.com", Name: name, Type: typ, Egress: egress},
	}
}

func TestMutationsOutsideThePermissionsAreDeniedBeforeTheProvider(t *testing.T) {
	all := []string{"create", "update", "patch", "delete"}
	acme := token.Permission{
		Verbs: all, Zones: []string{"example.com"}, Names: []string{"_acme-challenge", "_acme-challenge.**"}, Types: []string{"TXT"},
	}

	for name, tc := range map[string]struct {
		perm      token.Permission
		name, typ string
		egress    dnsgatev1.Egress
		code      codes.Code
		category  dnsgatev1.Error_Category
	}{
		"verb not granted": {
			token.Permission{Verbs: []string{"get", "list"}},
			"_acme-challenge.www", "TXT", 0,
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"name outside the filter": {
			acme, "www", "TXT", 0, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"type outside the filter": {
			acme, "_acme-challenge.www", "A", 0, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"agent egress asked, gateway egress only": {
			token.Permission{Verbs: all, Egress: []string{"gateway"}},
			"_acme-challenge.www", "TXT", dnsgatev1.Egress_EGRESS_AGENT,
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
		"gateway egress asked, agent egress only": {
			token.Permission{Verbs: all, Egress: []string{"agent"}},
			"_acme-challenge.www", "TXT", dnsgatev1.Egress_EGRESS_GATEWAY,
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newMutationHarness(t)

			tok := h.mint(t, nil, tc.perm)

			for verb, req := range mutations(tc.name, tc.typ, tc.egress) {
				err := h.call(t, tok, req)
				if status.Code(err) != tc.code {
					t.Errorf("%s: error = %v, want code %v", verb, err, tc.code)

					continue
				}

				wantError(t, err, tc.code, tc.category)
			}

			if calls := h.fake.Calls(); len(calls) != 0 {
				t.Errorf("provider calls = %+v, want none", calls)
			}
		})
	}

	t.Run("zone outside the filter", func(t *testing.T) {
		h := newMutationHarness(t)

		tok := h.mint(t, nil, acme)

		for verb, req := range mutations("_acme-challenge", "TXT", 0) {
			switch req := req.(type) {
			case *dnsgatev1.CreateRecordRequest:
				req.Zone = "example.org"
			case *dnsgatev1.UpdateRecordRequest:
				req.Zone = "example.org"
			case *dnsgatev1.PatchRecordRequest:
				req.Zone = "example.org"
			case *dnsgatev1.DeleteRecordRequest:
				req.Zone = "example.org"
			}

			if err := h.call(t, tok, req); status.Code(err) != codes.PermissionDenied {
				t.Errorf("%s: error = %v, want permission denied", verb, err)
			}
		}

		if calls := h.fake.Calls(); len(calls) != 0 {
			t.Errorf("provider calls = %+v, want none", calls)
		}
	})
}

func TestEachMutationAndDenialIsAuditedOnceWithoutSecrets(t *testing.T) {
	h := newMutationHarness(t)

	tok := h.mint(t, nil, token.Permission{
		Verbs: []string{"create", "update", "patch", "delete"}, Names: []string{"_acme-challenge.**"}, Types: []string{"TXT"},
	})

	gw := dnsgatev1.Egress_EGRESS_GATEWAY

	requests := []any{
		&dnsgatev1.CreateRecordRequest{Zone: "Example.COM", Name: "_acme-challenge.api", Type: "txt", Egress: gw, Ttl: 300, Records: values(`"a"`)},
		&dnsgatev1.PatchRecordRequest{Zone: "example.com", Name: "_acme-challenge.api", Type: "TXT", Egress: gw, Add: values(`"b"`)},
		&dnsgatev1.UpdateRecordRequest{Zone: "example.com", Name: "_acme-challenge.api", Type: "TXT", Egress: gw, Ttl: 60, Records: values(`"c"`)},
		&dnsgatev1.DeleteRecordRequest{Zone: "example.com", Name: "_acme-challenge.api", Type: "TXT", Egress: gw},
		// Denied: a name outside the token's.
		&dnsgatev1.DeleteRecordRequest{Zone: "example.com", Name: "www.apps", Type: "TXT", Egress: gw},
	}

	var errs []error

	for i, req := range requests {
		err := h.call(t, tok, req)
		if i < 4 && err != nil {
			t.Fatalf("request %d: %v", i, err)
		}

		errs = append(errs, err)
	}

	events := h.auditEvents(t)
	if len(events) != len(requests) {
		t.Fatalf("audit events =\n%v\nwant one per request", h.audit.String())
	}

	ids := map[any]bool{}

	for i, verb := range []string{"create", "patch", "update", "delete", "delete"} {
		e := events[i]

		name, result := "_acme-challenge.api", "ok"
		if i == 4 {
			name, result = "www.apps", "denied"
		}

		for field, want := range map[string]any{
			"event": "records." + verb, "verb": verb, "result": result,
			"service_account": "app", "jti": "tok_01TESTAPP", "provider": "cloudflare",
			"zone": "example.com", "record_name": name, "record_type": "TXT",
			"requested_egress": "gateway",
		} {
			if e[field] != want {
				t.Errorf("event %d %s = %v, want %v", i, field, e[field], want)
			}
		}

		// The update modifies "a" into "c" and deletes "b"; the denial
		// changes nothing and has no Changeset.
		if want := []any{float64(1), float64(1), float64(2), float64(1), nil}[i]; e["changes_applied"] != want {
			t.Errorf("event %d changes_applied = %v, want %v", i, e["changes_applied"], want)
		}

		if wantEgress := map[bool]any{true: "gateway", false: nil}[result == "ok"]; e["egress"] != wantEgress {
			t.Errorf("event %d egress = %v, want %v", i, e["egress"], wantEgress)
		}

		if _, ok := e["duration_ms"].(float64); !ok {
			t.Errorf("event %d duration_ms = %v, want a number", i, e["duration_ms"])
		}

		if id, _ := e["request_id"].(string); !strings.HasPrefix(id, "req_") || ids[id] {
			t.Errorf("event %d request_id = %v, want a new req_ ID", i, e["request_id"])
		}

		ids[e["request_id"]] = true
	}

	if events[4]["category"] != "permission_denied" {
		t.Errorf("denial category = %v, want permission_denied", events[4]["category"])
	}

	for _, secret := range []string{cfToken, tok} {
		if strings.Contains(h.audit.String(), secret) || strings.Contains(h.logs.String(), secret) || strings.Contains(errs[4].Error(), secret) {
			t.Errorf("a secret leaked:\naudit:\n%s\nlogs:\n%s\nerror: %v", h.audit.String(), h.logs.String(), errs[4])
		}
	}
}

func TestProviderFailuresOfAChangesetReachTheClientAsCategories(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		code     codes.Code
		category dnsgatev1.Error_Category
		status   int32
	}{
		"record refused": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 400, Messages: []string{rawProviderMessage}},
			codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD, 400,
		},
		"denied": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 403, Messages: []string{rawProviderMessage}},
			codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, 403,
		},
		"rate limited": {
			&dnsprovider.APIError{Provider: "cloudflare", StatusCode: 429, Messages: []string{rawProviderMessage}},
			codes.ResourceExhausted, dnsgatev1.Error_CATEGORY_RATE_LIMITED, 429,
		},
		"records changed at the provider": {
			fmt.Errorf("%s: %w", rawProviderMessage, dnsprovider.ErrStale),
			codes.Aborted, dnsgatev1.Error_CATEGORY_CONFLICT, 0,
		},
		"record collides": {
			fmt.Errorf("%s: %w", rawProviderMessage, dnsprovider.ErrConflict),
			codes.Aborted, dnsgatev1.Error_CATEGORY_CONFLICT, 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newMutationHarness(t)
			h.fake.Fail(providertest.OpApply, tc.err)

			root := h.onboard(t, onboardRequest())

			for verb, req := range mutations("_acme-challenge.www", "TXT", 0) {
				switch r := req.(type) {
				case *dnsgatev1.PatchRecordRequest:
					r.Add = values(`"new"`)
				case *dnsgatev1.CreateRecordRequest:
					r.Name = "_acme-challenge.api"
				}

				err := h.call(t, root, req)
				if status.Code(err) != tc.code {
					t.Errorf("%s: error = %v, want code %v", verb, err, tc.code)

					continue
				}

				wantError(t, err, tc.code, tc.category)

				if got := dnsgatev1.ErrorDetail(status.Convert(err)).GetProviderStatus(); got != tc.status {
					t.Errorf("%s: provider status = %d, want %d", verb, got, tc.status)
				}

				if strings.Contains(err.Error(), "cloudflare says") {
					t.Errorf("%s: error %v carries the raw Provider answer", verb, err)
				}
			}

			if strings.Contains(h.audit.String(), "cloudflare says") {
				t.Errorf("audit log carries the raw Provider answer:\n%s", h.audit.String())
			}

			for _, e := range h.auditEvents(t)[1:] {
				if e["result"] != "failed" || e["category"] != tc.category.Name() || e["provider_status"] != statusField(tc.status) {
					t.Errorf("audit event = %v, want failed, category %s, provider status %d", e, tc.category.Name(), tc.status)
				}
			}
		})
	}
}

func TestAChangeTheProviderFailsFailsTheCallAndTheOthersStayMade(t *testing.T) {
	h := newHarness(t)
	h.addZones()

	// The Provider takes one change at a time and refuses the new value.
	h.fake.FailChanges(func(c dnsprovider.Change) error {
		if c.After.Value == "192.0.2.13" {
			return &dnsprovider.APIError{Provider: "cloudflare", StatusCode: 400}
		}

		return nil
	})

	root := h.onboard(t, onboardRequest())

	_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "www.apps", Type: "A", Ttl: 300, Records: values("192.0.2.12", "192.0.2.13"),
	})
	wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD)

	if got, want := h.readSet(t, root, "www.apps", "A"), "www.apps A 120 192.0.2.11,192.0.2.12"; got != want {
		t.Errorf("RRset = %q, want %q: the change the Provider made stays", got, want)
	}

	events := h.auditEvents(t)[1:]
	if len(events) != 1 || events[0]["event"] != "records.update" || events[0]["result"] != "failed" || events[0]["provider_status"] != float64(400) {
		t.Errorf("audit events = %v, want one failed records.update, provider status 400", events)
	}

	if got := events[0]["changes_applied"]; got != float64(1) {
		t.Errorf("changes_applied = %v, want 1: the audit log keeps the change the Provider made", got)
	}
}

func TestUpdateRecordOfAnRRsetTheZoneLacksIsNotFound(t *testing.T) {
	h := newMutationHarness(t)

	root := h.onboard(t, onboardRequest())

	_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "A", Ttl: 300, Records: values("192.0.2.1"),
	})
	wantError(t, err, codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND)

	wantChangesets(t, h)
}

// serveFactory restarts the Gateway with the fake Provider's Factory as
// edit leaves it, standing in for a Provider type that declares what
// edit sets.
func (h *harness) serveFactory(t *testing.T, edit func(*dnsprovider.Factory)) {
	t.Helper()

	f := h.fake.Factory()
	edit(&f)

	h.providers = dnsprovider.Registry{"cloudflare": f}
	h.serve(t, h.keys)
}

func TestTheTTLIsCheckedAgainstTheRangeOfTheProviderType(t *testing.T) {
	h := newMutationHarness(t)
	h.serveFactory(t, func(f *dnsprovider.Factory) { f.TTL = dnsprovider.TTLRange{Min: 600, Max: 86400} })

	root := h.onboard(t, onboardRequest())

	_, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "A", Ttl: 300, Records: values("192.0.2.1"),
	})
	wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD)

	_, err = h.client.PatchRecord(t.Context(), &dnsgatev1.PatchRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "A", Ttl: 300, Add: values("192.0.2.1"),
	})
	wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD)

	if _, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "A", Ttl: 600, Records: values("192.0.2.1"),
	}); err != nil {
		t.Errorf("CreateRecord with a TTL in range: %v", err)
	}
}

// serveProxied restarts the Gateway with a Provider type whose A, AAAA
// and CNAME records carry a writable "proxied" Record Extra, and every
// record a "comment" one that writes keep.
func (h *harness) serveProxied(t *testing.T) {
	t.Helper()

	h.serveFactory(t, func(f *dnsprovider.Factory) {
		f.Extras = []dnsprovider.ExtraSpec{
			dnsprovider.ProxiedExtra("A", "AAAA", "CNAME"),
			{Key: "comment", Label: "Comment", Kind: dnsprovider.ExtraString},
		}
	})
}

func TestCreateRecordSetsTheRecordExtrasOfEachValue(t *testing.T) {
	h := newMutationHarness(t)
	h.serveProxied(t)

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "A", Ttl: 300, Records: []*dnsgatev1.RecordValue{
			{Value: "192.0.2.30", Extras: map[string]string{"proxied": "true"}},
			{Value: "192.0.2.31"},
		},
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	want := "api A 300 192.0.2.30{proxied=true},192.0.2.31"
	if got := sortedSet(resp.GetRecordSet()); got != want {
		t.Errorf("created RRset = %q, want %q", got, want)
	}

	wantChangesets(t, h, []string{
		"add A api.example.com 192.0.2.30{proxied=true} 300",
		"add A api.example.com 192.0.2.31 300",
	})

	if got := h.readSet(t, root, "api", "A"); got != want {
		t.Errorf("RRset read back = %q, want %q", got, want)
	}
}

// newProxiedHarness returns a mutation harness serving a Provider type
// as serveProxied does, whose example.com holds only the A RRset of www:
// 192.0.2.1, proxied and with a comment, and 192.0.2.2, with no Record
// Extras.
func newProxiedHarness(t *testing.T) *harness {
	t.Helper()

	h := newMutationHarness(t)
	h.fake.SetRecords("z-com",
		dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{"proxied": "true", "comment": "web"}},
		dnsprovider.Record{ID: "r2", Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 300},
	)
	h.serveProxied(t)

	return h
}

func TestWritesMergeTheRecordExtrasOfHeldValuesPerKey(t *testing.T) {
	for name, tc := range map[string]struct {
		records []*dnsgatev1.RecordValue
		changes []string
		want    string
	}{
		"a key sent sets its Record Extra": {
			[]*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: map[string]string{"proxied": "false"}}, {Value: "192.0.2.2", Extras: map[string]string{"proxied": "true"}}},
			[]string{
				"modify A www.example.com 192.0.2.1{comment=web;proxied=true} 300 -> 192.0.2.1{comment=web;proxied=false} 300",
				"modify A www.example.com 192.0.2.2 300 -> 192.0.2.2{proxied=true} 300",
			},
			"www A 300 192.0.2.1{comment=web;proxied=false},192.0.2.2{proxied=true}",
		},
		"a key sent as empty clears its Record Extra": {
			[]*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: map[string]string{"proxied": ""}}, {Value: "192.0.2.2"}},
			[]string{"modify A www.example.com 192.0.2.1{comment=web;proxied=true} 300 -> 192.0.2.1{comment=web;proxied=} 300"},
			"www A 300 192.0.2.1{comment=web},192.0.2.2",
		},
		"a key not sent keeps its Record Extra": {
			values("192.0.2.1", "192.0.2.2"),
			nil,
			"www A 300 192.0.2.1{comment=web;proxied=true},192.0.2.2",
		},
		"the proxy flag off is no proxy flag": {
			[]*dnsgatev1.RecordValue{{Value: "192.0.2.1"}, {Value: "192.0.2.2", Extras: map[string]string{"proxied": "false"}}},
			nil,
			"www A 300 192.0.2.1{comment=web;proxied=true},192.0.2.2",
		},
		"a new value in a held record's place keeps the Record Extras writes keep": {
			[]*dnsgatev1.RecordValue{{Value: "192.0.2.2"}, {Value: "192.0.2.9"}},
			[]string{"modify A www.example.com 192.0.2.1{comment=web;proxied=true} 300 -> 192.0.2.9{comment=web;proxied=} 300"},
			"www A 300 192.0.2.2,192.0.2.9{comment=web}",
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newProxiedHarness(t)

			root := h.onboard(t, onboardRequest())

			resp, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: tc.records,
			})
			if err != nil {
				t.Fatalf("UpdateRecord: %v", err)
			}

			if got := sortedSet(resp.GetRecordSet()); got != tc.want {
				t.Errorf("updated RRset = %q, want %q", got, tc.want)
			}

			if tc.changes == nil {
				wantChangesets(t, h)
			} else {
				wantChangesets(t, h, tc.changes)
			}

			if got := h.readSet(t, root, "www", "A"); got != tc.want {
				t.Errorf("RRset read back = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPatchRecordChangesTheRecordExtrasOfAValueItAddsAgain(t *testing.T) {
	h := newProxiedHarness(t)

	root := h.onboard(t, onboardRequest())

	resp, err := h.client.PatchRecord(t.Context(), &dnsgatev1.PatchRecordRequest{
		Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 600,
		Add: []*dnsgatev1.RecordValue{{Value: "192.0.2.2", Extras: map[string]string{"proxied": "true"}}},
	})
	if err != nil {
		t.Fatalf("PatchRecord: %v", err)
	}

	// The value keeps its TTL: patch sets the TTL of the values it adds.
	want := "www A 300 192.0.2.1{comment=web;proxied=true},192.0.2.2{proxied=true}"
	if got := sortedSet(resp.GetRecordSet()); got != want {
		t.Errorf("patched RRset = %q, want %q", got, want)
	}

	wantChangesets(t, h, []string{"modify A www.example.com 192.0.2.2 300 -> 192.0.2.2{proxied=true} 300"})
}

func TestRecordExtrasAWriteCannotSetAreRefused(t *testing.T) {
	type extras = map[string]string

	for name, tc := range map[string]struct {
		typ     string
		records []*dnsgatev1.RecordValue
	}{
		"a key the Provider does not read":             {"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: extras{"color": "blue"}}, {Value: "192.0.2.2"}}},
		"a key the Provider does not read on the type": {"TXT", []*dnsgatev1.RecordValue{{Value: "v=1", Extras: extras{"proxied": "true"}}}},
		"a key the Provider does not read, cleared":    {"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: extras{"color": ""}}, {Value: "192.0.2.2"}}},
		"a bool that is not true or false":             {"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: extras{"proxied": "yes"}}, {Value: "192.0.2.2"}}},
		"a key writes keep, changed on a held value":   {"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: extras{"comment": "api"}}, {Value: "192.0.2.2"}}},
		"a key writes keep, cleared on a held value":   {"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1", Extras: extras{"comment": ""}}, {Value: "192.0.2.2"}}},
		"a key writes keep, set on a held value":       {"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1"}, {Value: "192.0.2.2", Extras: extras{"comment": "web"}}}},
		"a key writes keep, set on a value not held": {
			"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1"}, {Value: "192.0.2.2"}, {Value: "192.0.2.3", Extras: extras{"comment": "web"}}},
		},
		"a key writes keep, cleared on a value not held": {
			"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.1"}, {Value: "192.0.2.2"}, {Value: "192.0.2.3", Extras: extras{"comment": ""}}},
		},
		"a key writes keep, on a new value in a held record's place": {
			"A", []*dnsgatev1.RecordValue{{Value: "192.0.2.2"}, {Value: "192.0.2.9", Extras: extras{"comment": "web"}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newProxiedHarness(t)

			root := h.onboard(t, onboardRequest())

			_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: tc.typ, Ttl: 300, Records: tc.records,
			})
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD)

			wantChangesets(t, h)

			if got, want := h.readSet(t, root, "www", "A"), "www A 300 192.0.2.1{comment=web;proxied=true},192.0.2.2"; got != want {
				t.Errorf("RRset = %q, want it untouched: %q", got, want)
			}
		})
	}
}

func TestRecordExtrasAWriteKeepsMayBeSentAsHeld(t *testing.T) {
	h := newProxiedHarness(t)

	root := h.onboard(t, onboardRequest())

	_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: []*dnsgatev1.RecordValue{
			{Value: "192.0.2.1", Extras: map[string]string{"comment": "web", "proxied": "false"}},
			{Value: "192.0.2.2", Extras: map[string]string{"comment": ""}},
		},
	})
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	wantChangesets(t, h, []string{"modify A www.example.com 192.0.2.1{comment=web;proxied=true} 300 -> 192.0.2.1{comment=web;proxied=false} 300"})
}

func TestPatchRecordRefusesRecordExtrasAWriteCannotSet(t *testing.T) {
	for name, add := range map[string]*dnsgatev1.RecordValue{
		"a key the Provider does not read":          {Value: "192.0.2.3", Extras: map[string]string{"color": "blue"}},
		"a key writes keep, on a held value":        {Value: "192.0.2.2", Extras: map[string]string{"comment": "web"}},
		"a key writes keep, cleared on a new value": {Value: "192.0.2.3", Extras: map[string]string{"comment": ""}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newProxiedHarness(t)

			root := h.onboard(t, onboardRequest())

			_, err := h.client.PatchRecord(t.Context(), &dnsgatev1.PatchRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Add: []*dnsgatev1.RecordValue{add},
			})
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD)

			wantChangesets(t, h)
		})
	}
}

func TestTheAuditEventOfAMutationShowsItsChangeset(t *testing.T) {
	h := newProxiedHarness(t)

	root := h.onboard(t, onboardRequest())

	if _, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: []*dnsgatev1.RecordValue{
			{Value: "192.0.2.1", Extras: map[string]string{"proxied": "false"}},
			{Value: "192.0.2.3"},
		},
	}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	events := h.auditEvents(t)
	got, err := json.Marshal(events[len(events)-1]["changes"])
	if err != nil {
		t.Fatal(err)
	}

	// The proxy toggle shows in the Record Extras before and after.
	want := `[` +
		`{"after":{"extras":{"comment":"web","proxied":"false"},"ttl":300,"value":"192.0.2.1"},` +
		`"before":{"extras":{"comment":"web","proxied":"true"},"ttl":300,"value":"192.0.2.1"},"kind":"modify"},` +
		`{"after":{"ttl":300,"value":"192.0.2.3"},"before":{"ttl":300,"value":"192.0.2.2"},"kind":"modify"}` +
		`]`
	if string(got) != want {
		t.Errorf("audited changes =\n%s\nwant\n%s", got, want)
	}
}

func TestTheAuditEventShowsOnlyTheRecordExtrasTheProviderTypeNames(t *testing.T) {
	h := newMutationHarness(t)
	h.fake.SetRecords("z-com",
		dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{"comment": "web", "labels": `{"team":"web"}`}},
	)
	h.serveFactory(t, func(f *dnsprovider.Factory) {
		f.Extras = []dnsprovider.ExtraSpec{
			dnsprovider.ProxiedExtra("A"),
			{Key: "comment", Label: "Comment", Kind: dnsprovider.ExtraString},
			{Key: dnsprovider.ExtraOther, Label: "Other fields", Kind: dnsprovider.ExtraJSON},
		}
	})

	root := h.onboard(t, onboardRequest())

	if _, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: []*dnsgatev1.RecordValue{
			{Value: "192.0.2.1", Extras: map[string]string{"proxied": "true"}},
		},
	}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	wantChangesets(t, h, []string{
		`modify A www.example.com 192.0.2.1{comment=web;labels={"team":"web"}} 300 -> 192.0.2.1{comment=web;labels={"team":"web"};proxied=true} 300`,
	})

	events := h.auditEvents(t)
	got, err := json.Marshal(events[len(events)-1]["changes"])
	if err != nil {
		t.Fatal(err)
	}

	// labels, a field the Provider passes through unmodelled, stays out.
	want := `[` +
		`{"after":{"extras":{"comment":"web","proxied":"true"},"ttl":300,"value":"192.0.2.1"},` +
		`"before":{"extras":{"comment":"web"},"ttl":300,"value":"192.0.2.1"},"kind":"modify"}` +
		`]`
	if string(got) != want {
		t.Errorf("audited changes =\n%s\nwant\n%s", got, want)
	}
}

// expected returns an Expected RRset of ttl and records.
func expected(ttl uint32, records ...*dnsgatev1.RecordValue) *dnsgatev1.ExpectedRRset {
	return &dnsgatev1.ExpectedRRset{Ttl: ttl, Records: records}
}

// heldWeb returns the record 192.0.2.1 of the RRset newProxiedHarness
// holds, with its Record Extras.
func heldWeb() *dnsgatev1.RecordValue {
	return &dnsgatev1.RecordValue{Value: "192.0.2.1", Extras: map[string]string{"comment": "web", "proxied": "true"}}
}

// withExtras returns v's value with extras in place of its Record Extras.
func withExtras(v *dnsgatev1.RecordValue, extras map[string]string) *dnsgatev1.RecordValue {
	return &dnsgatev1.RecordValue{Value: v.GetValue(), Extras: extras}
}

// heldRRset is the Expected RRset of the RRset newProxiedHarness holds.
func heldRRset() *dnsgatev1.ExpectedRRset {
	return expected(300, heldWeb(), &dnsgatev1.RecordValue{Value: "192.0.2.2"})
}

// heldSet is the RRset newProxiedHarness holds, formatted by sortedSet.
const heldSet = "www A 300 192.0.2.1{comment=web;proxied=true},192.0.2.2"

// wantStaleRRset checks that err refuses a write of event as built on a
// stale RRset: a conflict, with no Changeset applied, the RRset www A
// left as want, and the write audited as failed with category conflict.
func wantStaleRRset(t *testing.T, h *harness, err error, event, root, want string) {
	t.Helper()

	wantError(t, err, codes.Aborted, dnsgatev1.Error_CATEGORY_CONFLICT)

	wantChangesets(t, h)

	if got := h.readSet(t, root, "www", "A"); got != want {
		t.Errorf("RRset = %q, want it untouched: %q", got, want)
	}

	events := h.auditEvents(t)[1:]
	if len(events) < 1 || events[0]["event"] != event || events[0]["result"] != "failed" || events[0]["category"] != "conflict" {
		t.Errorf("audit events = %v, want a failed %s, category conflict", events, event)
	}
}

func TestUpdateRecordBuiltOnAnRRsetThatNoLongerMatchesIsAConflict(t *testing.T) {
	type extras = map[string]string

	plain := &dnsgatev1.RecordValue{Value: "192.0.2.2"}

	for name, expect := range map[string]*dnsgatev1.ExpectedRRset{
		"a value the RRset does not hold": expected(300, heldWeb(), &dnsgatev1.RecordValue{Value: "192.0.2.3"}),
		"a value fewer":                   expected(300, heldWeb()),
		"another TTL":                     expected(600, heldWeb(), plain),
		"another Record Extra":            expected(300, withExtras(heldWeb(), extras{"comment": "api", "proxied": "true"}), plain),
		"a Record Extra fewer":            expected(300, withExtras(heldWeb(), extras{"comment": "web"}), plain),
		"a Record Extra the record lacks": expected(300, heldWeb(), withExtras(plain, extras{"proxied": "true"})),
	} {
		t.Run(name, func(t *testing.T) {
			h := newProxiedHarness(t)

			root := h.onboard(t, onboardRequest())

			_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 600, Records: values("192.0.2.9"), Expect: expect,
			})
			wantStaleRRset(t, h, err, "records.update", root, heldSet)
		})
	}
}

func TestUpdateRecordBuiltOnTheRRsetTheZoneHoldsIsApplied(t *testing.T) {
	h := newProxiedHarness(t)

	root := h.onboard(t, onboardRequest())

	// The values in another order, a proxy flag off and a Record Extra
	// given as "" match the RRset.
	expect := expected(300,
		&dnsgatev1.RecordValue{Value: "192.0.2.2", Extras: map[string]string{"proxied": "false", "comment": ""}},
		heldWeb(),
	)

	if _, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: values("192.0.2.1", "192.0.2.3"), Expect: expect,
	}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	wantChangesets(t, h, []string{"modify A www.example.com 192.0.2.2 300 -> 192.0.2.3 300"})
}

func TestDeleteRecordChecksItsExpectedRRset(t *testing.T) {
	t.Run("one that no longer matches is a conflict", func(t *testing.T) {
		h := newProxiedHarness(t)

		root := h.onboard(t, onboardRequest())

		_, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
			Token: root, Zone: "example.com", Name: "www", Type: "A", Expect: expected(300, &dnsgatev1.RecordValue{Value: "192.0.2.2"}),
		})
		wantStaleRRset(t, h, err, "records.delete", root, heldSet)
	})

	t.Run("one that matches deletes the RRset", func(t *testing.T) {
		h := newProxiedHarness(t)

		root := h.onboard(t, onboardRequest())

		if _, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
			Token: root, Zone: "example.com", Name: "www", Type: "A", Expect: heldRRset(),
		}); err != nil {
			t.Fatalf("DeleteRecord: %v", err)
		}

		if got := h.readSet(t, root, "www", "A"); got != "" {
			t.Errorf("RRset read back = %q, want it gone", got)
		}
	})
}

func TestAWriteWithAnExpectedRRsetTheZoneLacksIsAConflict(t *testing.T) {
	for name, write := range map[string]struct {
		event string
		call  func(h *harness, root string) error
	}{
		"update": {"records.update", func(h *harness, root string) error {
			_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: values("192.0.2.9"), Expect: heldRRset(),
			})

			return err
		}},
		"delete": {"records.delete", func(h *harness, root string) error {
			_, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Expect: heldRRset(),
			})

			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newProxiedHarness(t)
			h.fake.SetRecords("z-com")

			root := h.onboard(t, onboardRequest())

			wantStaleRRset(t, h, write.call(h, root), write.event, root, "")
		})
	}
}

func TestAnExpectedRRsetThatGivesAValueTwiceIsInvalid(t *testing.T) {
	twice := expected(300, heldWeb(), heldWeb())

	for name, call := range map[string]func(h *harness, root string) error{
		"update": func(h *harness, root string) error {
			_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Ttl: 300, Records: values("192.0.2.9"), Expect: twice,
			})

			return err
		},
		"delete": func(h *harness, root string) error {
			_, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
				Token: root, Zone: "example.com", Name: "www", Type: "A", Expect: twice,
			})

			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newProxiedHarness(t)

			root := h.onboard(t, onboardRequest())

			wantError(t, call(h, root), codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)

			wantChangesets(t, h)
		})
	}
}

func TestAnExpectedRRsetMatchesEachHeldRecordOnce(t *testing.T) {
	h := newProxiedHarness(t)
	h.fake.SetRecords("z-com",
		dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300},
		dnsprovider.Record{ID: "r2", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300},
	)

	root := h.onboard(t, onboardRequest())

	_, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
		Token: root, Zone: "example.com", Name: "www", Type: "A",
		Expect: expected(300, &dnsgatev1.RecordValue{Value: "192.0.2.1"}, &dnsgatev1.RecordValue{Value: "192.0.2.2"}),
	})
	wantStaleRRset(t, h, err, "records.delete", root, "www A 300 192.0.2.1,192.0.2.1")
}
