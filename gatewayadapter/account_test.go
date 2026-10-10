package gatewayadapter_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// zonesListed reports whether the fake Provider was asked for its Zones.
func zonesListed(h *harness) bool {
	return slices.ContainsFunc(h.fake.Calls(), func(c providertest.Call) bool { return c.Op == providertest.OpZones })
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
	h.fake.Fail(providertest.OpZones, &dnsprovider.APIError{Provider: "cloudflare", StatusCode: 403})

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
