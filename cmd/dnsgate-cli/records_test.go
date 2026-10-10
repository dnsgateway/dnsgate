package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// fakeProviders returns a fake Provider scripted with example.com and
// example.org, and a Registry offering it as "cloudflare".
func fakeProviders() (*providertest.Provider, dnsprovider.Registry) {
	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: "z-com", Name: "example.com", State: dnsprovider.HostingActive},
			dnsprovider.Record{ID: "r1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300},
			dnsprovider.Record{ID: "r2", Type: "A", Name: "www.apps.example.com", Value: "192.0.2.10", TTL: 300},
			dnsprovider.Record{ID: "r3", Type: "A", Name: "www.apps.example.com", Value: "192.0.2.11", TTL: 300},
			dnsprovider.Record{ID: "r4", Type: "TXT", Name: "_acme-challenge.example.com", Value: `"abc"`, TTL: 60},
		).
		AddZone(dnsprovider.Zone{ID: "z-org", Name: "example.org", State: dnsprovider.HostingPending})
	fake.SetProxiableTypes("A", "AAAA", "CNAME")

	return fake, dnsprovider.Registry{"cloudflare": fake.Factory()}
}

type zoneJSON struct {
	Name        string   `json:"name"`
	State       string   `json:"state"`
	Nameservers []string `json:"nameservers"`
}

type recordSetJSON struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	TTL     uint32            `json:"ttl"`
	Records []recordValueJSON `json:"records"`
}

type recordValueJSON struct {
	Value  string            `json:"value"`
	Extras map[string]string `json:"extras"`
}

// format formats s as "name type ttl value,value", its values sorted,
// each followed by its Record Extras, if any, as "{key=extra;...}".
func (s recordSetJSON) format() string {
	var values []string

	for _, r := range s.Records {
		v := r.Value

		if len(r.Extras) > 0 {
			var kvs []string
			for _, k := range slices.Sorted(maps.Keys(r.Extras)) {
				kvs = append(kvs, k+"="+r.Extras[k])
			}

			v += "{" + strings.Join(kvs, ";") + "}"
		}

		values = append(values, v)
	}

	slices.Sort(values)

	return fmt.Sprintf("%s %s %d %s", s.Name, s.Type, s.TTL, strings.Join(values, ","))
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
	fake, providers := fakeProviders()

	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config, providers)

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

	if got, want := decode[recordSetJSON](t, out).format(), "www.apps A 300 192.0.2.10,192.0.2.11"; got != want {
		t.Errorf("record get = %q, want %q", got, want)
	}

	// The fake Provider was built from the onboarded Provider Credential.
	if calls := fake.Calls(); len(calls) == 0 || calls[0].Fields["token"] != testCFToken {
		t.Errorf("provider calls = %+v, want the Provider built from the Provider Credential", calls)
	}

	for _, secret := range []string{testCFToken, testBootstrapSecret, root} {
		if strings.Contains(gw.Audit.String(), secret) || strings.Contains(gw.Logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", gw.Audit.String(), gw.Logs.String())
		}
	}
}

func TestListsNoteAPartialViewOnStderrEndToEnd(t *testing.T) {
	_, providers := fakeProviders()

	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config, providers)

	root, derived := onboardAndIssue(t, env, gw, `permissions:
  - verbs: [list]
    resources: [zones, records]
    zones: [example.com]
    types: [A]
`, "app")

	for name, tc := range map[string]struct {
		tok, zones, records, zonesNote, recordsNote string
	}{
		"full view": {
			tok:     root,
			zones:   "example.com example.org",
			records: "@ A,_acme-challenge TXT,www.apps A",
		},
		"partial view": {
			tok:         derived[0],
			zones:       "example.com",
			records:     "@ A,www.apps A",
			zonesNote:   "note: partial view: the token's Permissions do not cover every zone\n",
			recordsNote: "note: partial view: the token's Permissions do not cover every name and type in example.com\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, errOut, err := runClientStderr(t, env, gw, "zone", "list", "--token", tc.tok)
			if err != nil {
				t.Fatalf("zone list: %v", err)
			}

			var zones []string
			for _, z := range decode[[]zoneJSON](t, out) {
				zones = append(zones, z.Name)
			}

			if got := strings.Join(zones, " "); got != tc.zones {
				t.Errorf("zone list = %q, want %q", got, tc.zones)
			}

			if errOut != tc.zonesNote {
				t.Errorf("zone list stderr = %q, want %q", errOut, tc.zonesNote)
			}

			out, errOut, err = runClientStderr(t, env, gw, "record", "list", "--zone", "example.com", "--token", tc.tok)
			if err != nil {
				t.Fatalf("record list: %v", err)
			}

			var sets []string
			for _, s := range decode[[]recordSetJSON](t, out) {
				sets = append(sets, s.Name+" "+s.Type)
			}

			if got := strings.Join(sets, ","); got != tc.records {
				t.Errorf("record list = %q, want %q", got, tc.records)
			}

			if errOut != tc.recordsNote {
				t.Errorf("record list stderr = %q, want %q", errOut, tc.recordsNote)
			}
		})
	}
}

func TestListHelpMentionsThePartialViewNote(t *testing.T) {
	for _, args := range [][]string{{"zone", "list", "--help"}, {"record", "list", "--help"}} {
		out, err := runCLI(t, args...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}

		if !strings.Contains(out, "partial view") || !strings.Contains(out, "stderr") {
			t.Errorf("%v help lacks the partial view note on stderr:\n%s", args, out)
		}
	}
}

func TestReadRecordsFailures(t *testing.T) {
	fake, providers := fakeProviders()

	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config, providers)

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
		"RRset not found": {
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

	audit := gw.Audit.String()
	if !strings.Contains(audit, `"category":"unauthenticated"`) {
		t.Errorf("audit output lacks the denials:\n%s", audit)
	}

	// Only the not-found read reached the Provider.
	for _, c := range fake.Calls() {
		if c.Op == providertest.OpRecords && c.RecordFilter.Type != "AAAA" {
			t.Errorf("provider call %+v, want only the AAAA read", c)
		}
	}
}

func TestChangeRecordsEndToEnd(t *testing.T) {
	_, providers := fakeProviders()

	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config, providers)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	root := strings.TrimSpace(out)
	t.Setenv("DNSGATE_TOKEN", root)
	t.Setenv("DNSGATE_ZONE", "example.com")

	for _, step := range []struct {
		args []string
		// want is the RRset printed, "" for nothing.
		want string
	}{
		{
			[]string{"record", "create", "api", "A", "192.0.2.30", "192.0.2.31", "--ttl", "600", "--extra", "proxied=true"},
			"api A 600 192.0.2.30{proxied=true},192.0.2.31{proxied=true}",
		},
		{[]string{"record", "update", "api", "A", "192.0.2.31", "192.0.2.32", "--ttl", "300"}, "api A 300 192.0.2.31{proxied=true},192.0.2.32"},
		{
			[]string{"record", "patch", "api", "A", "--add", "192.0.2.31", "--add", "192.0.2.32", "--extra", "proxied="},
			"api A 300 192.0.2.31,192.0.2.32",
		},
		{[]string{"record", "patch", "_acme-challenge", "TXT", "--add", `"def"`, "--add", `"g,h"`}, `_acme-challenge TXT 60 "abc","def","g,h"`},
		{[]string{"record", "patch", "_acme-challenge", "TXT", "--remove", `"abc"`}, `_acme-challenge TXT 60 "def","g,h"`},
		{[]string{"record", "patch", "_acme-challenge", "TXT", "--remove", `"def"`, "--remove", `"g,h"`}, ""},
		{[]string{"record", "delete", "api", "A"}, ""},
	} {
		out, err := runClient(t, env, gw, step.args...)
		if err != nil {
			t.Fatalf("%v: %v", step.args, err)
		}

		got := ""
		if out != "" {
			got = decode[recordSetJSON](t, out).format()
		}

		if got != step.want {
			t.Errorf("%v printed %q, want %q", step.args, got, step.want)
		}
	}

	out, err = runClient(t, env, gw, "record", "list")
	if err != nil {
		t.Fatalf("record list: %v", err)
	}

	var names []string
	for _, s := range decode[[]recordSetJSON](t, out) {
		names = append(names, s.Name+" "+s.Type)
	}

	if want := []string{"@ A", "www.apps A"}; !slices.Equal(names, want) {
		t.Errorf("record list = %v, want %v", names, want)
	}

	for _, verb := range []string{"create", "update", "patch", "delete"} {
		if !strings.Contains(gw.Audit.String(), `"event":"records.`+verb+`"`) {
			t.Errorf("audit output lacks records.%s:\n%s", verb, gw.Audit.String())
		}
	}

	for _, secret := range []string{testCFToken, testBootstrapSecret, root} {
		if strings.Contains(gw.Audit.String(), secret) || strings.Contains(gw.Logs.String(), secret) {
			t.Errorf("server output contains a secret:\naudit:\n%s\nlogs:\n%s", gw.Audit.String(), gw.Logs.String())
		}
	}
}

func TestChangeRecordsFailures(t *testing.T) {
	fake, providers := fakeProviders()

	env := servertest.NewEnv(t)
	gw := startServer(t, env.Config, providers)

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	out, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	t.Setenv("DNSGATE_TOKEN", strings.TrimSpace(out))
	t.Setenv("DNSGATE_ZONE", "example.com")

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"create without TTL":       {[]string{"record", "create", "api", "A", "192.0.2.1"}, "no TTL"},
		"create without values":    {[]string{"record", "create", "api", "A", "--ttl", "300"}, "requires at least 3 arg(s)"},
		"update without TTL":       {[]string{"record", "update", "www.apps", "A", "192.0.2.1"}, "no TTL"},
		"patch with nothing to do": {[]string{"record", "patch", "www.apps", "A"}, "nothing to add or remove"},
		"create of an RRset held": {
			[]string{"record", "create", "www.apps", "A", "192.0.2.1", "--ttl", "300"}, "conflict: the RRset already exists",
		},
		"update of an RRset the zone lacks": {
			[]string{"record", "update", "api", "A", "192.0.2.1", "--ttl", "300"}, "not found",
		},
		"malformed value": {
			[]string{"record", "create", "api", "A", "www", "--ttl", "300"}, "invalid record",
		},
		"Record Extra without a value": {
			[]string{"record", "create", "api", "A", "192.0.2.1", "--ttl", "300", "--extra", "proxied"}, "--extra takes KEY=VALUE",
		},
		"Record Extra the Provider does not read": {
			[]string{"record", "create", "api", "A", "192.0.2.1", "--ttl", "300", "--extra", "color=blue"}, "invalid record",
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

	for _, c := range fake.Calls() {
		if c.Op == providertest.OpCreateRecord || c.Op == providertest.OpUpdateRecord || c.Op == providertest.OpDeleteRecord {
			t.Errorf("provider call %+v, want no write", c)
		}
	}
}
