package gateway_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
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
// NAME VALUE TTL" or "modify TYPE NAME VALUE TTL -> VALUE TTL".
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
	rec := func(r dnsprovider.Record) string { return fmt.Sprintf("%s %s %s %d", r.Type, r.Name, r.Value, r.TTL) }

	switch c.Kind {
	case dnsprovider.ChangeAdd:
		return "add " + rec(c.After)
	case dnsprovider.ChangeModify:
		return fmt.Sprintf("modify %s -> %s %d", rec(c.Before), c.After.Value, c.After.TTL)
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
		Token: root, Zone: "example.com", Name: "API", Type: "a", Ttl: 600, Values: []string{"192.0.2.30", "192.0.2.31"},
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
		Token: root, Zone: "example.com", Name: "www.apps", Type: "A", Ttl: 300, Values: []string{"192.0.2.99"},
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
				Token: root, Zone: "example.com", Name: "api", Type: tc.typ, Ttl: tc.ttl, Values: tc.values,
			})
			wantError(t, err, tc.code, tc.category)

			if ops := h.providerCalls(); slices.ContainsFunc(ops, func(op providertest.Op) bool { return op != providertest.OpNew }) {
				t.Errorf("provider calls = %v, want none past building it", ops)
			}

			events := h.auditEvents(t)[1:]
			if len(events) != 1 || events[0]["event"] != "records.create" || events[0]["result"] != "denied" || events[0]["category"] != tc.category.Name() {
				t.Errorf("audit events = %v, want one denied records.create, category %s", events, tc.category.Name())
			}
		})
	}
}

// sortedSet formats an RRset as recordSets does, its values sorted.
func sortedSet(s *dnsgatev1.RecordSet) string {
	values := slices.Sorted(slices.Values(s.GetValues()))

	return fmt.Sprintf("%s %s %d %s", s.GetName(), s.GetType(), s.GetTtl(), strings.Join(values, ","))
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
				Token: root, Zone: "example.com", Name: "www.apps", Type: "A", Ttl: tc.ttl, Values: tc.values,
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
		Token: root, Zone: "example.com", Name: "@", Type: "A", Ttl: 300, Values: []string{"192.0.2.1"},
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
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Add: []string{`"def"`}},
			[]string{`add TXT ` + acme + ` "def" 60`},
			`_acme-challenge.www TXT 60 "abc","def"`,
		},
		"add a value with its own TTL": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Ttl: 120, Add: []string{`"def"`}},
			[]string{`add TXT ` + acme + ` "def" 120`},
			`_acme-challenge.www TXT 60 "abc","def"`,
		},
		"remove one value of two": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Remove: []string{"192.0.2.10"}},
			[]string{"delete A www.apps.example.com 192.0.2.10 300"},
			"www.apps A 120 192.0.2.11",
		},
		"add one value and remove another": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.www", Type: "TXT", Add: []string{`"def"`}, Remove: []string{`"abc"`}},
			[]string{`modify TXT ` + acme + ` "abc" 60 -> "def" 60`},
			`_acme-challenge.www TXT 60 "def"`,
		},
		"add a value held and remove one not held": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: []string{"192.0.2.10"}, Remove: []string{"192.0.2.99"}},
			nil,
			"www.apps A 120 192.0.2.10,192.0.2.11",
		},
		"add to an RRset the zone lacks": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.api", Type: "TXT", Ttl: 120, Add: []string{`"xyz"`}},
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
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: []string{"192.0.2.10"}, Remove: []string{"192.0.2.10"}},
			dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
		"value added twice": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: []string{"192.0.2.12", "192.0.2.12"}},
			dnsgatev1.Error_CATEGORY_INVALID_REQUEST,
		},
		"malformed value": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Add: []string{"www"}},
			dnsgatev1.Error_CATEGORY_INVALID_RECORD,
		},
		"TTL out of range": {
			&dnsgatev1.PatchRecordRequest{Name: "www.apps", Type: "A", Ttl: 5, Add: []string{"192.0.2.12"}},
			dnsgatev1.Error_CATEGORY_INVALID_RECORD,
		},
		"no TTL for a new RRset": {
			&dnsgatev1.PatchRecordRequest{Name: "_acme-challenge.api", Type: "TXT", Add: []string{`"xyz"`}},
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
			if len(events) != 1 || events[0]["event"] != "records.patch" || events[0]["result"] != "denied" || events[0]["category"] != tc.category.Name() {
				t.Errorf("audit events = %v, want one denied records.patch, category %s", events, tc.category.Name())
			}
		})
	}
}

func TestUpdateRecordOfAnRRsetTheZoneLacksIsNotFound(t *testing.T) {
	h := newMutationHarness(t)

	root := h.onboard(t, onboardRequest())

	_, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "A", Ttl: 300, Values: []string{"192.0.2.1"},
	})
	wantError(t, err, codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND)

	wantChangesets(t, h)
}
