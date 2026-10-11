package gatewayadapter_test

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"
)

// readAll reads every Record of example.com through p.
func readAll(t *testing.T, p dnsprovider.Provider) []dnsprovider.Record {
	t.Helper()

	set, err := p.ListRecords(t.Context(), zone(t, p), dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	return set.Records
}

func TestCreateRecordCreatesAnRRset(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.root)
	z := zone(t, p)

	add := dnsprovider.Record{Type: "TXT", Name: "_acme-challenge.example.com", Value: "token", TTL: 300}

	got, err := p.CreateRecord(t.Context(), z, add)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	if !sameContent(got, add) || got.ID == "" {
		t.Errorf("CreateRecord = %+v, want %+v with an ID", got, add)
	}

	wantWrites(t, h, "create _acme-challenge TXT 300 [token]")

	if records := readAll(t, p); len(records) != 1 || records[0].ID != got.ID {
		t.Errorf("Records = %+v, want the Record created, with its ID", records)
	}
}

func TestCreateRecordAddsAValueToAnRRset(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	z := zone(t, p)

	add := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.3", TTL: 300, Extras: map[string]string{dnsprovider.ExtraProxied: "true"}}
	if _, err := p.CreateRecord(t.Context(), z, add); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	// The values already held are sent bare: the Gateway keeps their
	// Record Extras.
	wantWrites(t, h, "update www A 300 [192.0.2.1 192.0.2.2 192.0.2.3{proxied=true}] expect 300 [192.0.2.1{proxied=true} 192.0.2.2{proxied=false}]")

	want := append(wwwRecords(), add)
	if got := readAll(t, p); !slices.EqualFunc(got, want, sameContent) {
		t.Errorf("Records = %+v, want %+v", got, want)
	}
}

func TestCreateRecordConflictsWithAnIdenticalRecord(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)

	_, err := p.CreateRecord(t.Context(), zone(t, p), dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Errorf("CreateRecord = %v, want ErrConflict", err)
	}

	wantWrites(t, h)
}

// readWWW reads the www A Records through p.
func readWWW(t *testing.T, p dnsprovider.Provider) []dnsprovider.Record {
	t.Helper()

	set, err := p.ListRecords(t.Context(), zone(t, p), dnsprovider.RecordFilter{Type: "A", Contains: "www."})
	if err != nil {
		t.Fatal(err)
	}

	return set.Records
}

func TestUpdateRecordUpdatesTheRRsetNamingItAsExpected(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	before := readWWW(t, p)[1]

	after := before
	after.Value, after.TTL = "192.0.2.3", 600

	got, err := p.UpdateRecord(t.Context(), zone(t, p), before, after)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	if !sameContent(got, after) {
		t.Errorf("UpdateRecord = %+v, want %+v", got, after)
	}

	// The new value is sent with its proxy flag; the other keeps its own.
	// The RRset takes the new TTL whole.
	wantWrites(t, h, "update www A 600 [192.0.2.1 192.0.2.3{proxied=false}] expect 300 [192.0.2.1{proxied=true} 192.0.2.2{proxied=false}]")

	want := []dnsprovider.Record{
		{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 600, Extras: map[string]string{dnsprovider.ExtraProxied: "true"}},
		{Type: "A", Name: "www.example.com", Value: "192.0.2.3", TTL: 600, Extras: map[string]string{dnsprovider.ExtraProxied: "false"}},
	}
	if got := readWWW(t, p); !slices.EqualFunc(got, want, sameContent) {
		t.Errorf("Records = %+v, want %+v", got, want)
	}
}

func TestUpdateRecordClearsARemovedRecordExtra(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	before := readWWW(t, p)[0]

	after := before
	after.Extras = nil

	if _, err := p.UpdateRecord(t.Context(), zone(t, p), before, after); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	wantWrites(t, h, "update www A 300 [192.0.2.2 192.0.2.1{proxied=}] expect 300 [192.0.2.1{proxied=true} 192.0.2.2{proxied=false}]")

	if got := readWWW(t, p); len(got) != 2 || got[0].Extras != nil {
		t.Errorf("Records = %+v, want 192.0.2.1 without its proxy flag", got)
	}
}

func TestUpdateRecordOfAGoneRecordIsNotFound(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	before := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.9", TTL: 300}

	after := before
	after.Value = "192.0.2.10"

	if _, err := p.UpdateRecord(t.Context(), zone(t, p), before, after); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("UpdateRecord = %v, want ErrNotFound", err)
	}

	wantWrites(t, h)
}

func TestDeleteRecordDeletesTheLastValueAndUpdatesOtherwise(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	z := zone(t, p)
	records := readWWW(t, p)

	if err := p.DeleteRecord(t.Context(), z, records[0]); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	if err := p.DeleteRecord(t.Context(), z, records[1]); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	wantWrites(t, h,
		"update www A 300 [192.0.2.2] expect 300 [192.0.2.1{proxied=true} 192.0.2.2{proxied=false}]",
		"delete www A expect 300 [192.0.2.2{proxied=false}]",
	)

	if got := readAll(t, p); len(got) != 0 {
		t.Errorf("Records = %+v, want none", got)
	}
}

func TestApplyChangesetReportsAMoveWrittenOnlyInPart(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)
	h.fake.FailChanges(func(c dnsprovider.Change) error {
		if c.Kind == dnsprovider.ChangeAdd {
			return &dnsprovider.APIError{Provider: "cloudflare", StatusCode: 400}
		}

		return nil
	})

	p := h.provider(t, h.root)
	before := readWWW(t, p)[1]

	after := before
	after.Name = "api.example.com"

	_, err := p.UpdateRecord(t.Context(), zone(t, p), before, after)
	if err == nil || !strings.Contains(err.Error(), "www A is written already") {
		t.Errorf("UpdateRecord = %v, want an error saying www A is written already", err)
	}

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("UpdateRecord = %v, want the Gateway's invalid record as HTTP 400", err)
	}
}

func TestWriteBuiltOnAnRRsetThatChangedSinceConflicts(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	before := readWWW(t, p)[1]

	// Another writer adds a value between the Gateway Adapter's read of
	// the RRset and its write.
	h.beforeWrite = func() {
		h.fake.SetRecords("z1", append(wwwRecords(),
			dnsprovider.Record{ID: "r9", Type: "A", Name: "www.example.com", Value: "192.0.2.9", TTL: 300})...)
	}

	if err := p.DeleteRecord(t.Context(), zone(t, p), before); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Errorf("DeleteRecord = %v, want ErrConflict", err)
	}

	h.beforeWrite = nil

	if got := valuesOf(readWWW(t, p)); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2", "192.0.2.9"}) {
		t.Errorf("Records = %v, want the other writer's RRset untouched", got)
	}
}

func TestWritesNeedNoPatch(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	tok := h.derive(t, &dnsgatev1.Permission{
		Verbs:     []string{"get", "list", "create", "update", "delete"},
		Resources: []string{"zones", "records"},
	})
	p := h.provider(t, tok)
	z := zone(t, p)
	records := readWWW(t, p)

	if _, err := p.CreateRecord(t.Context(), z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.3", TTL: 300}); err != nil {
		t.Errorf("CreateRecord: %v", err)
	}

	after := records[0]
	after.TTL = 120

	if _, err := p.UpdateRecord(t.Context(), z, records[0], after); err != nil {
		t.Errorf("UpdateRecord: %v", err)
	}

	if err := p.DeleteRecord(t.Context(), z, records[1]); err != nil {
		t.Errorf("DeleteRecord: %v", err)
	}

	for _, w := range h.writes() {
		if strings.HasPrefix(w, "patch") {
			t.Errorf("the Gateway Adapter patched: %s", w)
		}
	}
}

// comment is a Record Extra the Provider keeps on write, as Cloudflare
// keeps a record's comment.
var comment = dnsprovider.ExtraSpec{Key: "comment", Label: "Comment", Kind: dnsprovider.ExtraString}

// commentedWWW are the www A Records, the first with a comment.
func commentedWWW() []dnsprovider.Record {
	records := wwwRecords()
	records[0].Extras = map[string]string{dnsprovider.ExtraProxied: "true", "comment": "hi"}

	return records
}

func TestUpdateRecordLeavesAKeptRecordExtraItOmits(t *testing.T) {
	h := newHarness(t, comment)
	h.fake.SetRecords("z1", commentedWWW()...)

	p := h.provider(t, h.root)
	before := readWWW(t, p)[0]

	after := before
	after.Extras = map[string]string{dnsprovider.ExtraProxied: "false"}

	if _, err := p.UpdateRecord(t.Context(), zone(t, p), before, after); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	// The comment is not sent: the Provider keeps it, and the Gateway
	// refuses a write that clears it.
	wantWrites(t, h, "update www A 300 [192.0.2.2 192.0.2.1{proxied=false}] expect 300 [192.0.2.1{comment=hi,proxied=true} 192.0.2.2{proxied=false}]")

	if got := readWWW(t, p); got[0].Extras["comment"] != "hi" {
		t.Errorf("Records = %+v, want 192.0.2.1 to keep its comment", got)
	}
}

func TestUpdateRecordThatOmitsOnlyAKeptRecordExtraWritesNothing(t *testing.T) {
	h := newHarness(t, comment)
	h.fake.SetRecords("z1", commentedWWW()...)

	p := h.provider(t, h.root)
	before := readWWW(t, p)[0]

	after := before
	after.Extras = map[string]string{dnsprovider.ExtraProxied: "true"}

	if _, err := p.UpdateRecord(t.Context(), zone(t, p), before, after); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	wantWrites(t, h)
}

func TestAWriteToAZoneTheProviderDoesNotHoldIsNotFound(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.root)
	gone := dnsprovider.Zone{ID: "example.net", Name: "example.net"}

	_, err := p.CreateRecord(t.Context(), gone, dnsprovider.Record{Type: "TXT", Name: "www.example.net", Value: "hi", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("CreateRecord = %v, want ErrNotFound", err)
	}

	err = p.DeleteRecord(t.Context(), gone, dnsprovider.Record{Type: "TXT", Name: "www.example.net", Value: "hi", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("DeleteRecord = %v, want ErrNotFound", err)
	}
}

func TestUpdateRecordGivingAnAbsentRecordExtraAsEmptyWritesNothing(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	before := readWWW(t, p)[0]

	after := before
	after.Extras = map[string]string{dnsprovider.ExtraProxied: "true", "comment": ""}

	if _, err := p.UpdateRecord(t.Context(), zone(t, p), before, after); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	wantWrites(t, h)
}
