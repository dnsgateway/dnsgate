package gatewayadapter_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/gatewayadapter"
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

// zonesListed reports whether the fake Provider was asked for its Zones.
func zonesListed(h *harness) bool {
	return slices.ContainsFunc(h.fake.Calls(), func(c providertest.Call) bool { return c.Op == providertest.OpListZones })
}

func TestAccountIsTheTokenAndProvesTheCredentialWhenItMayListZones(t *testing.T) {
	h := newHarness(t)

	info, err := h.provider(t, h.root).Account(t.Context())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	inspected, err := h.client.InspectToken(t.Context(), h.root)
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.Tenant{ID: inspected.GetJti(), Name: "root"}); info.Tenant != want {
		t.Errorf("Tenant = %+v, want %+v", info.Tenant, want)
	}

	if !zonesListed(h) {
		t.Error("Account did not list zones, which the Root Token may")
	}
}

func TestAccountListsNoZonesWithoutListOnZones(t *testing.T) {
	h := newHarness(t)
	tok := h.derive(t, &dnsgatev1.Permission{Verbs: []string{"get", "list"}, Resources: []string{"records"}})

	info, err := h.provider(t, tok).Account(t.Context())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	if info.Tenant.Name != "dnscli" || !strings.HasPrefix(info.Tenant.ID, "tok_") {
		t.Errorf("Tenant = %+v, want the Derived Token's jti and dnscli", info.Tenant)
	}

	if zonesListed(h) {
		t.Error("Account listed zones, which the token may not")
	}
}

func TestAccountFailsWhenTheProviderDeniesTheCredential(t *testing.T) {
	h := newHarness(t)
	h.fake.Fail(providertest.OpListZones, &dnsprovider.APIError{Provider: "cloudflare", StatusCode: 403})

	_, err := h.provider(t, h.root).Account(t.Context())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("Account = %v, want ErrUnauthorized", err)
	}
}

func TestAccountRefusesATokenTheGatewayDoesNotAccept(t *testing.T) {
	h := newHarness(t)

	_, err := h.provider(t, "not-a-token").Account(t.Context())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account = %v, want ErrUnauthorized", err)
	}

	if !strings.Contains(err.Error(), "Bound Token") {
		t.Errorf("Account = %v, want it to say a Bound Token is not usable", err)
	}
}

func TestTTLRangeAndRecordExtrasAreTheTokensProviderTypes(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.root)

	// Read before Account: the Gateway Adapter inspects the token itself.
	if got, want := dnsprovider.TTLRangeOf(p), (dnsprovider.TTLRange{Min: dnsprovider.MinTTL, Max: dnsprovider.MaxTTL, Auto: true}); got != want {
		t.Errorf("TTLRangeOf = %+v, want %+v", got, want)
	}

	if got := dnsprovider.ProxiableTypesOf(p); !slices.Equal(got, []string{"A", "AAAA", "CNAME"}) {
		t.Errorf("ProxiableTypesOf = %v, want A, AAAA and CNAME", got)
	}
}

func TestTTLRangeIsTheDefaultWhileTheProviderTypeIsUnknown(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, "not-a-token")

	if got := dnsprovider.TTLRangeOf(p); got != dnsprovider.DefaultTTLRange {
		t.Errorf("TTLRangeOf = %+v, want the default range", got)
	}

	if got := dnsprovider.ProxiableTypesOf(p); got != nil {
		t.Errorf("ProxiableTypesOf = %v, want none", got)
	}
}

func TestEachEgressIsAskedFor(t *testing.T) {
	h := newHarness(t)

	for field, want := range map[string]dnsgatev1.Egress{
		"auto":    dnsgatev1.Egress_EGRESS_UNSPECIFIED,
		"gateway": dnsgatev1.Egress_EGRESS_GATEWAY,
		"agent":   dnsgatev1.Egress_EGRESS_AGENT,
	} {
		t.Run(field, func(t *testing.T) {
			p, err := h.factory().New(map[string]string{gatewayadapter.FieldGateway: h.addr, gatewayadapter.FieldToken: h.root, gatewayadapter.FieldEgress: field})
			if err != nil {
				t.Fatal(err)
			}

			h.mu.Lock()
			h.requests = nil
			h.mu.Unlock()

			_, _ = p.ListZones(t.Context(), dnsprovider.ZoneFilter{})

			h.mu.Lock()
			defer h.mu.Unlock()

			if len(h.requests) != 1 || h.requests[0].GetListZones().GetEgress() != want {
				t.Errorf("requests = %v, want one zone list asking for %v", h.requests, want)
			}
		})
	}
}

// readProviderType reads the TTL range and proxiable types of p twice.
func readProviderType(p dnsprovider.Provider) {
	for range 2 {
		dnsprovider.TTLRangeOf(p)
		dnsprovider.ProxiableTypesOf(p)
	}
}

func TestTheProviderTypeIsInspectedOnce(t *testing.T) {
	h := newHarness(t)

	unknownType, err := gatewayadapter.Factory(gatewayadapter.WithRootCAs(h.roots), gatewayadapter.WithProviders(dnsprovider.Registry{})).
		New(map[string]string{gatewayadapter.FieldGateway: h.addr, gatewayadapter.FieldToken: h.root})
	if err != nil {
		t.Fatal(err)
	}

	for name, p := range map[string]dnsprovider.Provider{
		"known":         h.provider(t, h.root),
		"unknown":       unknownType,
		"token refused": h.provider(t, "not-a-token"),
	} {
		t.Run(name, func(t *testing.T) {
			h.mu.Lock()
			h.requests = nil
			h.mu.Unlock()

			readProviderType(p)

			if n := h.inspections(); n != 1 {
				t.Errorf("the Gateway Adapter inspected the token %d times, want once", n)
			}
		})
	}
}

func TestAccountLearnsTheProviderTypeEvenWhenUnknown(t *testing.T) {
	h := newHarness(t)

	p, err := gatewayadapter.Factory(gatewayadapter.WithRootCAs(h.roots), gatewayadapter.WithProviders(dnsprovider.Registry{})).
		New(map[string]string{gatewayadapter.FieldGateway: h.addr, gatewayadapter.FieldToken: h.root})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.Account(t.Context()); err != nil {
		t.Fatalf("Account: %v", err)
	}

	readProviderType(p)

	if n := h.inspections(); n != 1 {
		t.Errorf("the Gateway Adapter inspected the token %d times, want once, by Account", n)
	}
}

func TestADeleteNeedsNoProviderType(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", dnsprovider.Record{ID: "r1", Type: "TXT", Name: "old.example.com", Value: "bye", TTL: 300})

	p := h.provider(t, h.root)

	if err := p.DeleteRecord(t.Context(), zone(t, p), readAll(t, p)[0]); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	if n := h.inspections(); n != 0 {
		t.Errorf("the Gateway Adapter inspected the token %d times, want never", n)
	}
}
