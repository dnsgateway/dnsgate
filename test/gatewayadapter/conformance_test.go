package gatewayadapter_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// dnsprovider exports no conformance suite; these tests hold the Gateway
// Adapter to the Provider contract as dnsprovider.Apply and its consumers
// rely on it.

func TestConformanceApplyRoundTripsAChangeset(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	z := zone(t, p)
	records := readWWW(t, p)

	add := dnsprovider.Record{Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 3600}
	after := records[0]
	after.Value = "192.0.2.5"

	res, err := dnsprovider.Apply(t.Context(), p, dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: add},
		{Kind: dnsprovider.ChangeModify, Before: records[0], After: after},
		{Kind: dnsprovider.ChangeDelete, Before: records[1]},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for i, r := range res.Results {
		if r.Err != nil {
			t.Errorf("change %d: %v", i, r.Err)
		}
	}

	// Each Record a write returns is the one Records reads, ID and all.
	got := readAll(t, p)
	for _, r := range []dnsprovider.Record{res.Results[0].Record, res.Results[1].Record} {
		if !slices.ContainsFunc(got, func(g dnsprovider.Record) bool { return g.ID == r.ID && sameContent(g, r) }) {
			t.Errorf("Records = %+v, want %+v among them", got, r)
		}
	}

	if len(got) != 2 {
		t.Errorf("Records = %+v, want the MX and the modified A alone", got)
	}
}

func TestConformanceApplyRefusesAStaleChangeset(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	z := zone(t, p)
	before := readWWW(t, p)[0]

	// The Record's proxy flag changes at the Provider after it was read.
	changed := wwwRecords()
	changed[0].Extras = map[string]string{dnsprovider.ExtraProxied: "false"}
	h.fake.SetRecords("z1", changed...)

	_, err := dnsprovider.Apply(t.Context(), p, dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeDelete, Before: before},
	}})
	if !errors.Is(err, dnsprovider.ErrStale) {
		t.Errorf("Apply = %v, want ErrStale", err)
	}

	wantWrites(t, h)
}

func TestConformanceRecordsOfAnRRsetShareItsTTL(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	z := zone(t, p)
	records := readWWW(t, p)

	after := records[0]
	after.TTL = 120

	if _, err := p.UpdateRecord(t.Context(), z, records[0], after); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	for _, r := range readWWW(t, p) {
		if r.TTL != 120 {
			t.Errorf("Record %+v, want TTL 120: an RRset has one TTL", r)
		}
	}
}

func TestConformanceZoneIDsWorkForEveryCall(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)

	zoneSet, err := p.ListZones(t.Context(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	// A Zone from Zones reads its Records as one from Zone does.
	set, err := p.ListRecords(t.Context(), zoneSet.Zones[0], dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if len(set.Records) != 2 || set.Serial != 0 {
		t.Errorf("Records = %+v, want the two www values and no serial", set)
	}
}
