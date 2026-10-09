package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

// useFakeProvider makes the Gateways the test starts call a fake
// Provider as "cloudflare", scripted with example.com and example.org.
func useFakeProvider(t *testing.T) *providertest.Provider {
	t.Helper()

	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: "z-com", Name: "example.com", State: dnsprovider.HostingActive},
			dnsprovider.Record{ID: "r1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300},
			dnsprovider.Record{ID: "r2", Type: "A", Name: "www.apps.example.com", Value: "192.0.2.10", TTL: 300},
			dnsprovider.Record{ID: "r3", Type: "A", Name: "www.apps.example.com", Value: "192.0.2.11", TTL: 300},
			dnsprovider.Record{ID: "r4", Type: "TXT", Name: "_acme-challenge.example.com", Value: `"abc"`, TTL: 60},
		).
		AddZone(dnsprovider.Zone{ID: "z-org", Name: "example.org", State: dnsprovider.HostingPending})

	saved := providers
	providers = func() dnsprovider.Registry { return dnsprovider.Registry{"cloudflare": fake.Factory()} }

	t.Cleanup(func() { providers = saved })

	return fake
}

type zoneJSON struct {
	Name        string   `json:"name"`
	State       string   `json:"state"`
	Nameservers []string `json:"nameservers"`
}

type recordSetJSON struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	TTL    uint32   `json:"ttl"`
	Values []string `json:"values"`
}

func decode[T any](t *testing.T, out string) T {
	t.Helper()

	var v T
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}

	return v
}

func TestReadZonesAndRecordsEndToEnd(t *testing.T) {
	fake := useFakeProvider(t)

	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	root := strings.TrimSpace(out)
	t.Setenv("DNSGATE_TOKEN", root)

	out, err = runClient(t, env, gw, "zone", "list")
	if err != nil {
		t.Fatalf("zone list: %v", err)
	}

	zones := decode[[]zoneJSON](t, out)
	if len(zones) != 2 || zones[0].Name != "example.com" || zones[0].State != "active" || zones[1].Name != "example.org" || zones[1].State != "pending" {
		t.Errorf("zone list = %+v, want example.com active and example.org pending", zones)
	}

	out, err = runClient(t, env, gw, "zone", "get", "example.com")
	if err != nil {
		t.Fatalf("zone get: %v", err)
	}

	if z := decode[zoneJSON](t, out); z.Name != "example.com" || z.State != "active" {
		t.Errorf("zone get = %+v, want example.com active", z)
	}

	out, err = runClient(t, env, gw, "record", "list", "--zone", "example.com")
	if err != nil {
		t.Fatalf("record list: %v", err)
	}

	var names []string
	for _, s := range decode[[]recordSetJSON](t, out) {
		names = append(names, s.Name+" "+s.Type)
	}

	if want := []string{"@ A", "_acme-challenge TXT", "www.apps A"}; !slices.Equal(names, want) {
		t.Errorf("record list = %v, want %v", names, want)
	}

	t.Setenv("DNSGATE_ZONE", "example.com")

	out, err = runClient(t, env, gw, "record", "get", "www.apps", "A")
	if err != nil {
		t.Fatalf("record get: %v", err)
	}

	want := recordSetJSON{Name: "www.apps", Type: "A", TTL: 300, Values: []string{"192.0.2.10", "192.0.2.11"}}
	if got := decode[recordSetJSON](t, out); got.Name != want.Name || got.Type != want.Type || got.TTL != want.TTL || !slices.Equal(got.Values, want.Values) {
		t.Errorf("record get = %+v, want %+v", got, want)
	}

	// The fake Provider was built from the onboarded Provider Credential.
	if calls := fake.Calls(); len(calls) == 0 || calls[0].Fields["token"] != testCFToken {
		t.Errorf("provider calls = %+v, want the Provider built from the Provider Credential", calls)
	}

	for _, secret := range []string{testCFToken, testBootstrapSecret, root} {
		if strings.Contains(gw.audit.String(), secret) || strings.Contains(gw.logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", gw.audit.String(), gw.logs.String())
		}
	}
}

func TestReadRecordsFailures(t *testing.T) {
	fake := useFakeProvider(t)

	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	root := strings.TrimSpace(out)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"agent egress": {
			[]string{"record", "list", "--zone", "example.com", "--egress", "agent", "--token", root},
			"egress not supported: agent egress is not supported yet",
		},
		"unknown egress": {
			[]string{"record", "list", "--zone", "example.com", "--egress", "relay", "--token", root},
			`unknown egress "relay"`,
		},
		"no zone":  {[]string{"record", "list", "--token", root}, "no zone"},
		"no token": {[]string{"zone", "list"}, "no Service Token"},
		"invalid token": {
			[]string{"record", "get", "www", "A", "--zone", "example.com", "--token", root + "x"},
			"unauthenticated: invalid service token",
		},
		"record set not found": {
			[]string{"record", "get", "www", "AAAA", "--zone", "example.com", "--token", root},
			"not found",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runClient(t, env, gw, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want one containing %q", err, tc.want)
			}

			if out != "" {
				t.Errorf("printed %q, want nothing", out)
			}
		})
	}

	audit := gw.audit.String()
	if !strings.Contains(audit, `"category":"egress_not_supported"`) || !strings.Contains(audit, `"category":"unauthenticated"`) {
		t.Errorf("audit output lacks the denials:\n%s", audit)
	}

	// Only the not-found read reached the Provider.
	for _, c := range fake.Calls() {
		if c.Op == providertest.OpRecords && c.RecordFilter.Type != "AAAA" {
			t.Errorf("provider call %+v, want only the AAAA read", c)
		}
	}
}
