package permission_test

import (
	"testing"

	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/token"
)

func TestMatchName(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"@", "@", true},
		{"@", "www", false},
		{"www", "www", true},
		{"www", "WWW", true},
		{"www", "www.apps", false},
		{"www.apps", "www.apps", true},

		{"*", "www", true},
		{"*", "@", false},
		{"*", "www.apps", false},
		{"*.apps", "www.apps", true},
		{"*.apps", "apps", false},
		{"*.apps", "a.b.apps", false},
		{"*.apps", "www.other", false},
		{"www.*", "www.apps", true},

		{"**", "www", true},
		{"**", "a.b.c", true},
		{"**", "@", false},
		{"**.apps", "www.apps", true},
		{"**.apps", "a.b.apps", true},
		{"**.apps", "apps", false},
		{"_acme-challenge.**", "_acme-challenge.www", true},
		{"_acme-challenge.**", "_acme-challenge", false},
		{"a.**.z", "a.b.c.z", true},
		{"a.**.z", "a.z", false},
		{"**.*", "a.b", true},
		{"**.*", "a", false},

		// A wildcard Record's own name is a literal "*" label.
		{"*", "*", true},
		{"*.apps", "*.apps", true},
	} {
		if got := permission.MatchName(tc.pattern, tc.name); got != tc.want {
			t.Errorf("MatchName(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestAllows(t *testing.T) {
	records := permission.Request{
		Verb: "get", Resource: "records", Zone: "example.com", Name: "www.apps", Type: "A", Egress: "gateway",
	}

	for name, tc := range map[string]struct {
		perms []token.Permission
		req   permission.Request
		want  bool
	}{
		"no rules": {nil, records, false},
		"every filter left out allows records": {
			[]token.Permission{{Verbs: []string{"get"}}}, records, true,
		},
		"rule without verbs grants nothing": {
			[]token.Permission{{Resources: []string{"records"}}}, records, false,
		},
		"other verb": {
			[]token.Permission{{Verbs: []string{"list"}}}, records, false,
		},
		"resources left out means records only": {
			[]token.Permission{{Verbs: []string{"list"}}},
			permission.Request{Verb: "list", Resource: "zones", Zone: "example.com", Egress: "gateway"},
			false,
		},
		"zones granted explicitly": {
			[]token.Permission{{Verbs: []string{"list"}, Resources: []string{"zones"}}},
			permission.Request{Verb: "list", Resource: "zones", Zone: "example.com", Egress: "gateway"},
			true,
		},
		"matching zone, ignoring case and a trailing dot": {
			[]token.Permission{{Verbs: []string{"get"}, Zones: []string{"Example.COM."}}}, records, true,
		},
		"zone star": {
			[]token.Permission{{Verbs: []string{"get"}, Zones: []string{"*"}}}, records, true,
		},
		"other zone": {
			[]token.Permission{{Verbs: []string{"get"}, Zones: []string{"example.org"}}}, records, false,
		},
		"subzone is another zone": {
			[]token.Permission{{Verbs: []string{"get"}, Zones: []string{"apps.example.com"}}}, records, false,
		},
		"matching name pattern": {
			[]token.Permission{{Verbs: []string{"get"}, Names: []string{"*.apps"}}}, records, true,
		},
		"other name pattern": {
			[]token.Permission{{Verbs: []string{"get"}, Names: []string{"@", "*.web"}}}, records, false,
		},
		"names left out cover the apex": {
			[]token.Permission{{Verbs: []string{"get"}}},
			permission.Request{Verb: "get", Resource: "records", Zone: "example.com", Name: "@", Type: "A", Egress: "gateway"},
			true,
		},
		"matching type, ignoring case": {
			[]token.Permission{{Verbs: []string{"get"}, Types: []string{"txt", "a"}}}, records, true,
		},
		"type star": {
			[]token.Permission{{Verbs: []string{"get"}, Types: []string{"*"}}}, records, true,
		},
		"other type": {
			[]token.Permission{{Verbs: []string{"get"}, Types: []string{"TXT"}}}, records, false,
		},
		"matching egress": {
			[]token.Permission{{Verbs: []string{"get"}, Egress: []string{"gateway"}}}, records, true,
		},
		"other egress": {
			[]token.Permission{{Verbs: []string{"get"}, Egress: []string{"agent"}}}, records, false,
		},
		"rules add up": {
			[]token.Permission{
				{Verbs: []string{"get"}, Types: []string{"TXT"}},
				{Verbs: []string{"get"}, Names: []string{"www.apps"}},
			},
			records, true,
		},
		"one rule must allow every dimension": {
			[]token.Permission{
				{Verbs: []string{"get"}, Types: []string{"A"}, Zones: []string{"example.org"}},
				{Verbs: []string{"get"}, Types: []string{"TXT"}, Zones: []string{"example.com"}},
			},
			records, false,
		},
		"a zone request ignores names and types": {
			[]token.Permission{{Verbs: []string{"get"}, Resources: []string{"zones"}, Names: []string{"www"}, Types: []string{"TXT"}}},
			permission.Request{Verb: "get", Resource: "zones", Zone: "example.com", Egress: "gateway"},
			true,
		},
		"a request for any zone ignores zones": {
			[]token.Permission{{Verbs: []string{"list"}, Resources: []string{"zones"}, Zones: []string{"example.org"}}},
			permission.Request{Verb: "list", Resource: "zones", Egress: "gateway"},
			true,
		},
		"a request for any record of a zone ignores names and types": {
			[]token.Permission{{Verbs: []string{"list"}, Names: []string{"www"}, Types: []string{"TXT"}}},
			permission.Request{Verb: "list", Resource: "records", Zone: "example.com", Egress: "gateway"},
			true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := permission.Allows(tc.perms, tc.req); got != tc.want {
				t.Errorf("Allows = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestChooseEgress(t *testing.T) {
	both := []token.Permission{{Verbs: []string{"get"}}}
	gatewayOnly := []token.Permission{{Verbs: []string{"get"}, Egress: []string{"gateway"}}}
	agentOnly := []token.Permission{{Verbs: []string{"get"}, Egress: []string{"agent"}}}
	// Egress is chosen among the rules that allow the rest of the request.
	split := []token.Permission{
		{Verbs: []string{"get"}, Types: []string{"A"}, Egress: []string{"agent"}},
		{Verbs: []string{"get"}, Types: []string{"TXT"}, Egress: []string{"gateway"}},
	}

	for name, tc := range map[string]struct {
		perms     []token.Permission
		requested permission.Egress
		want      permission.Egress
		ok        bool
	}{
		"none asked, both allowed":        {both, "", "gateway", true},
		"none asked, gateway only":        {gatewayOnly, "", "gateway", true},
		"none asked, agent only":          {agentOnly, "", "agent", true},
		"none asked, agent for this type": {split, "", "agent", true},
		"gateway asked, both allowed":     {both, "gateway", "gateway", true},
		"agent asked, both allowed":       {both, "agent", "agent", true},
		"gateway asked, agent only":       {agentOnly, "gateway", "", false},
		"agent asked, gateway only":       {gatewayOnly, "agent", "", false},
		"none asked, nothing allowed":     {nil, "", "", false},
		"gateway asked, only for TXT":     {split, "gateway", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := permission.ChooseEgress(tc.perms, permission.Request{
				Verb: "get", Resource: "records", Zone: "example.com", Name: "www", Type: "A", Egress: tc.requested,
			})
			if got != tc.want || ok != tc.ok {
				t.Errorf("ChooseEgress = %q, %v, want %q, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}
