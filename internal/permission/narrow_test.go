package permission_test

import (
	"testing"

	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/token"
)

func TestCoversName(t *testing.T) {
	for _, tc := range []struct {
		parent []string
		child  string
		want   bool
	}{
		{[]string{"@"}, "@", true},
		{[]string{"@"}, "www", false},
		{[]string{"www"}, "@", false},
		{[]string{"www"}, "www", true},
		{[]string{"WWW"}, "www", true},
		{[]string{"www"}, "*", false},
		{[]string{"*"}, "www", true},
		{[]string{"*"}, "@", false},
		{[]string{"*"}, "*", true},
		{[]string{"*"}, "**", false},
		{[]string{"*"}, "www.apps", false},
		{[]string{"**"}, "@", false},
		{[]string{"**"}, "www", true},
		{[]string{"**"}, "*", true},
		{[]string{"**"}, "a.b.c", true},
		{[]string{"**"}, "**.*", true},
		{[]string{"*.apps"}, "www.apps", true},
		{[]string{"*.apps"}, "*.apps", true},
		{[]string{"*.apps"}, "**.apps", false},
		{[]string{"*.apps"}, "apps", false},
		{[]string{"**.apps"}, "*.apps", true},
		{[]string{"**.apps"}, "a.*.apps", true},
		{[]string{"**.apps"}, "**.apps", true},
		{[]string{"**.apps"}, "apps", false},
		{[]string{"**.apps"}, "**", false},
		{[]string{"*.**"}, "**.**", true},
		{[]string{"*.**"}, "**", false},
		{[]string{"**.**"}, "*.**", true},
		{[]string{"a.**.z"}, "a.b.*.z", true},
		{[]string{"a.**.z"}, "a.z", false},
		{[]string{"_acme-challenge.**"}, "_acme-challenge", false},
		{[]string{"_acme-challenge", "_acme-challenge.**"}, "_acme-challenge", true},
		{nil, "www", false},

		// A pattern may be covered only by several parent patterns together.
		{[]string{"@", "**"}, "@", true},
		{[]string{"*", "*.**"}, "**", true},
		{[]string{"*", "*.*"}, "**", false},
		{[]string{"www.*", "*.*"}, "*.*", true},
		{[]string{"a.*", "*.b"}, "*.*", false},
	} {
		if got := permission.CoversName(tc.parent, tc.child); got != tc.want {
			t.Errorf("CoversName(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}

func TestCovers(t *testing.T) {
	root := []token.Permission{{
		Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
		Resources: []string{"zones", "records", "tokens"},
		Zones:     []string{"*"},
		Names:     []string{"@", "**"},
		Types:     []string{"*"},
		Egress:    []string{"gateway", "agent"},
	}}
	records := []token.Permission{{
		Verbs:  []string{"get", "list"},
		Zones:  []string{"example.com"},
		Names:  []string{"**.apps"},
		Types:  []string{"A", "TXT"},
		Egress: []string{"gateway"},
	}}

	for name, tc := range map[string]struct {
		parent, child []token.Permission
		want          permission.Dimension
	}{
		"root covers itself":                {root, root, ""},
		"root covers every filter left out": {root, []token.Permission{{Verbs: []string{"get"}}}, ""},
		"root covers tokens":                {root, []token.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}}, ""},
		"filters left out on both":          {[]token.Permission{{Verbs: []string{"get"}}}, []token.Permission{{Verbs: []string{"get"}}}, ""},
		"no child rules":                    {records, nil, ""},
		"child rule without verbs":          {records, []token.Permission{{Zones: []string{"example.org"}}}, ""},
		"equal rules":                       {records, records, ""},
		"narrower on every filter": {records, []token.Permission{{
			Verbs: []string{"get"}, Resources: []string{"records"}, Zones: []string{"Example.COM."},
			Names: []string{"www.apps", "*.*.apps"}, Types: []string{"txt"}, Egress: []string{"gateway"},
		}}, ""},
		"rules add up across parent rules": {
			[]token.Permission{
				{Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"*"}},
				{Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"*.**"}},
				{Verbs: []string{"list"}, Zones: []string{"example.com"}},
			},
			[]token.Permission{{Verbs: []string{"get", "list"}, Zones: []string{"example.com"}, Names: []string{"**"}}},
			"",
		},

		"other verb":     {records, []token.Permission{{Verbs: []string{"delete"}, Zones: []string{"example.com"}}}, "verbs"},
		"other resource": {records, []token.Permission{{Verbs: []string{"get"}, Resources: []string{"zones"}}}, "resources"},
		"create on tokens without the parent having it": {
			[]token.Permission{{Verbs: []string{"create"}, Resources: []string{"records"}}},
			[]token.Permission{{Verbs: []string{"create"}, Resources: []string{"tokens"}}},
			"resources",
		},
		"resources left out means records": {
			[]token.Permission{{Verbs: []string{"get"}, Resources: []string{"zones"}}},
			[]token.Permission{{Verbs: []string{"get"}}},
			"resources",
		},
		"egress left out is any": {records, []token.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"www.apps"}, Types: []string{"A"},
		}}, "egress"},
		"other egress":          {records, []token.Permission{{Verbs: []string{"get"}, Egress: []string{"agent"}}}, "egress"},
		"zones left out is any": {records, []token.Permission{{Verbs: []string{"get"}, Egress: []string{"gateway"}}}, "zones"},
		"zone star":             {records, []token.Permission{{Verbs: []string{"get"}, Zones: []string{"*"}, Egress: []string{"gateway"}}}, "zones"},
		"other zone":            {records, []token.Permission{{Verbs: []string{"get"}, Zones: []string{"example.org"}, Egress: []string{"gateway"}}}, "zones"},
		"types left out is any": {records, []token.Permission{{Verbs: []string{"get"}, Zones: []string{"example.com"}, Egress: []string{"gateway"}}}, "types"},
		"type star": {records, []token.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"*"}, Egress: []string{"gateway"},
		}}, "types"},
		"other type": {records, []token.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"MX"}, Egress: []string{"gateway"},
		}}, "types"},
		"names left out is any": {records, []token.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}, Egress: []string{"gateway"},
		}}, "names"},
		"wider name": {records, []token.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}, Names: []string{"**"}, Egress: []string{"gateway"},
		}}, "names"},
		"apex outside the patterns": {records, []token.Permission{{
			Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}, Names: []string{"@"}, Egress: []string{"gateway"},
		}}, "names"},
		"one parent rule must cover each zone and type": {
			[]token.Permission{
				{Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"A"}},
				{Verbs: []string{"get"}, Zones: []string{"example.org"}, Types: []string{"TXT"}},
			},
			[]token.Permission{{Verbs: []string{"get"}, Zones: []string{"example.com"}, Types: []string{"TXT"}}},
			"types",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := permission.Covers(tc.parent, tc.child)
			if got != tc.want || ok != (tc.want == "") {
				t.Errorf("Covers = %q, %v, want %q", got, ok, tc.want)
			}
		})
	}
}
