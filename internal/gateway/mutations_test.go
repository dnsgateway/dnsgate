package gateway_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc/codes"

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
