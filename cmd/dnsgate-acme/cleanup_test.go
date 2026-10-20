package main

import (
	"fmt"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// A cleanup removes only its value: another validation still running at
// the same Challenge Target keeps its own.
func TestCleanupRemovesOnlyItsValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))
	d.wantPresented(t, tok, fqdn, challenge(2))

	d.wantCleanedUp(t, tok, fqdn, challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(2)+`"`)
}

// A cleanup of a value that is not there succeeds and changes nothing, so
// retries and double cleanups are harmless.
func TestCleanupOfAValueThatIsNotThereSucceeds(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))

	d.wantCleanedUp(t, tok, fqdn, challenge(2))
	d.wantCleanedUp(t, tok, fqdn, challenge(1))
	d.wantCleanedUp(t, tok, fqdn, challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A cleanup at a Challenge Target that holds no TXT RRset at all succeeds
// without a write: the Gateway's patch treats it as no change.
func TestCleanupWhereTheRRsetDoesNotExistSucceeds(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	e.providerNotWritten(t, func() {
		d.wantCleanedUp(t, tok, "_acme-challenge.example.com.", challenge(1))
	})

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// zoneRecords returns every record the fake Provider holds in the zone
// with zoneID, each as "type name TTL value", sorted.
func (e *e2e) zoneRecords(t *testing.T, zoneID, zone string) []string {
	t.Helper()

	set, err := e.Fake.ListRecords(t.Context(), dnsprovider.Zone{ID: zoneID, Name: zone}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]string, 0, len(set.Records))
	for _, r := range set.Records {
		out = append(out, fmt.Sprintf("%s %s %d %s", r.Type, r.Name, r.TTL, r.Value))
	}

	slices.Sort(out)

	return out
}

// A present then a cleanup of the same value leaves the zone as it was,
// a value already at the Challenge Target, with its own TTL, included.
func TestPresentThenCleanupLeavesTheZoneAsItWas(t *testing.T) {
	e := newE2E(t)
	e.Fake.SetRecords(zoneComID,
		dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300},
		dnsprovider.Record{ID: "r2", Type: "TXT", Name: "_acme-challenge.example.com", Value: `"` + challenge(2) + `"`, TTL: 300},
		dnsprovider.Record{ID: "r3", Type: "TXT", Name: "example.com", Value: `"v=spf1 -all"`, TTL: 3600},
	)

	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge", "_acme-challenge.**"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	before := e.zoneRecords(t, zoneComID, zoneCom)
	if len(before) != 3 {
		t.Fatalf("zone before = %q, want the 3 records set", before)
	}

	for _, fqdn := range []string{"_acme-challenge.example.com.", "_acme-challenge.www.example.com."} {
		d.wantPresented(t, tok, fqdn, challenge(1))
		d.wantCleanedUp(t, tok, fqdn, challenge(1))
	}

	if after := e.zoneRecords(t, zoneComID, zoneCom); !slices.Equal(after, before) {
		t.Errorf("zone after present and cleanup = %q, want as before %q", after, before)
	}
}
