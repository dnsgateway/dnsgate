package gatewayadapter_test

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

func TestZonesHaveTheirNameAsIDAndAreFiltered(t *testing.T) {
	h := newHarness(t)
	h.fake.AddZone(dnsprovider.Zone{ID: "z2", Name: "example.org", State: dnsprovider.HostingPending})

	p := h.provider(t, h.root)

	zones, err := p.Zones(t.Context(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	want := []dnsprovider.Zone{
		{ID: "example.com", Name: "example.com", State: dnsprovider.HostingActive, Nameservers: []string{"ns1.example.net"}},
		{ID: "example.org", Name: "example.org", State: dnsprovider.HostingPending},
	}
	if !slices.EqualFunc(zones, want, sameZone) {
		t.Errorf("Zones = %+v, want %+v", zones, want)
	}

	zones, err = p.Zones(t.Context(), dnsprovider.ZoneFilter{Contains: ".ORG."})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if !slices.EqualFunc(zones, want[1:], sameZone) {
		t.Errorf("Zones filtered by .ORG. = %+v, want %+v", zones, want[1:])
	}
}

func sameZone(a, b dnsprovider.Zone) bool {
	return a.ID == b.ID && a.Name == b.Name && a.State == b.State && slices.Equal(a.Nameservers, b.Nameservers)
}

func TestZoneReadsOneZoneByName(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.root)

	z, err := p.Zone(t.Context(), "example.com")
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}

	if want := (dnsprovider.Zone{ID: "example.com", Name: "example.com", State: dnsprovider.HostingActive, Nameservers: []string{"ns1.example.net"}}); !sameZone(z, want) {
		t.Errorf("Zone = %+v, want %+v", z, want)
	}

	if _, err := p.Zone(t.Context(), "example.net"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Zone of an unknown name = %v, want ErrNotFound", err)
	}
}

func TestZoneIsUnauthorizedWithoutGetOnZones(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.derive(t, &dnsgatev1.Permission{Verbs: []string{"get"}}))

	if _, err := p.Zone(t.Context(), "example.com"); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("Zone = %v, want ErrUnauthorized", err)
	}
}

// wwwRecords are an A RRset of two values, each with its proxy flag.
func wwwRecords() []dnsprovider.Record {
	return []dnsprovider.Record{
		{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{dnsprovider.ExtraProxied: "true"}},
		{ID: "r2", Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 300, Extras: map[string]string{dnsprovider.ExtraProxied: "false"}},
	}
}

func TestRecordsAreOnePerValueWithTheRRsetsTTLAndTheirOwnExtras(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", append(wwwRecords(),
		dnsprovider.Record{ID: "r3", Type: "TXT", Name: "example.com", Value: "v=spf1 -all", TTL: 3600},
		// The RRset's TTL is the lowest of its records'.
		dnsprovider.Record{ID: "r4", Type: "TXT", Name: "example.com", Value: "hello", TTL: 600},
	)...)

	p := h.provider(t, h.root)

	set, err := p.Records(t.Context(), zone(t, p), dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	want := []dnsprovider.Record{
		{Type: "TXT", Name: "example.com", Value: "v=spf1 -all", TTL: 600},
		{Type: "TXT", Name: "example.com", Value: "hello", TTL: 600},
		{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{dnsprovider.ExtraProxied: "true"}},
		{Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 300, Extras: map[string]string{dnsprovider.ExtraProxied: "false"}},
	}

	if !slices.EqualFunc(set.Records, want, sameContent) {
		t.Fatalf("Records = %+v, want %+v", set.Records, want)
	}

	ids := map[string]bool{}
	for _, r := range set.Records {
		if r.ID == "" || ids[r.ID] {
			t.Errorf("Record %+v has an empty or shared ID", r)
		}

		ids[r.ID] = true
	}

	again, err := p.Records(t.Context(), zone(t, p), dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if !slices.EqualFunc(set.Records, again.Records, func(a, b dnsprovider.Record) bool { return a.ID == b.ID }) {
		t.Error("the IDs changed between two reads of the same Records")
	}
}

// sameContent reports whether two Records are alike but for their IDs.
func sameContent(a, b dnsprovider.Record) bool {
	return a.Type == b.Type && a.Name == b.Name && a.Value == b.Value && a.TTL == b.TTL && maps.Equal(a.Extras, b.Extras)
}

func TestRecordsAreFiltered(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", append(wwwRecords(),
		dnsprovider.Record{ID: "r3", Type: "TXT", Name: "www.example.com", Value: "hello", TTL: 300},
		dnsprovider.Record{ID: "r4", Type: "A", Name: "api.example.com", Value: "192.0.2.9", TTL: 300},
	)...)

	p := h.provider(t, h.root)

	set, err := p.Records(t.Context(), zone(t, p), dnsprovider.RecordFilter{Type: "a", Contains: "WWW."})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	if got := valuesOf(set.Records); !slices.Equal(got, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Errorf("Records of type a holding WWW. = %v, want the www A values", got)
	}
}

func valuesOf(records []dnsprovider.Record) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Value)
	}

	return out
}
