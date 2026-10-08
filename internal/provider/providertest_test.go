package provider_test

import (
	"context"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

// The fake Provider stands in for a real one in dnsgate's tests: built
// from a Provider Credential through a Registry, it applies a Changeset
// and serves the Records back.
func TestFakeProviderRoundTripsARecord(t *testing.T) {
	ctx := context.Background()

	fake := providertest.New().AddZone(dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingActive})
	reg := dnsprovider.Registry{"fake": fake.Factory()}

	p, err := reg.New("fake", map[string]string{"token": "secret"})
	if err != nil {
		t.Fatal(err)
	}

	zone, err := p.Zone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	add := dnsprovider.Record{Type: "TXT", Name: "_acme-challenge.example.com", Value: `"token"`, TTL: 300}

	res, err := dnsprovider.Apply(ctx, p, dnsprovider.Changeset{
		Zone:    zone,
		Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: add}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := res.Results[0].Err; err != nil {
		t.Fatalf("adding the Record failed: %v", err)
	}

	set, err := p.Records(ctx, zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if len(set.Records) != 1 || set.Records[0].Name != add.Name || set.Records[0].Value != add.Value {
		t.Errorf("Records = %+v, want the added %+v", set.Records, add)
	}

	if calls := fake.Calls(); len(calls) == 0 || calls[0].Op != providertest.OpNew || calls[0].Fields["token"] != "secret" {
		t.Errorf("calls = %+v, want OpNew with the Provider Credential first", calls)
	}
}
