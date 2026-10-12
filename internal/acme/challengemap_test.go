package acme

import (
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
)

func TestResolveTakesTheLongestZoneThePermissionsAllow(t *testing.T) {
	patch := func(zone string, names ...string) *dnsgatev1.Permission {
		return &dnsgatev1.Permission{Verbs: []string{"patch"}, Zones: []string{zone}, Names: names, Types: []string{"TXT"}}
	}

	listSub := &dnsgatev1.Permission{Verbs: []string{"list"}, Zones: []string{"sub.example.com"}}

	for name, tc := range map[string]struct {
		perms []*dnsgatev1.Permission
		want  Target
	}{
		"the parent zone": {
			perms: []*dnsgatev1.Permission{patch("example.com", "_acme-challenge.www.sub")},
			want:  Target{Zone: "example.com", Name: "_acme-challenge.www.sub"},
		},
		"the longer zone": {
			perms: []*dnsgatev1.Permission{patch("example.com", "**"), patch("Sub.Example.com.", "**")},
			want:  Target{Zone: "sub.example.com", Name: "_acme-challenge.www"},
		},
		"not a longer zone where patch is not allowed": {
			perms: []*dnsgatev1.Permission{patch("example.com", "**"), listSub},
			want:  Target{Zone: "example.com", Name: "_acme-challenge.www.sub"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := Target{Name: "_acme-challenge.www.sub.example.com."}.resolve(tc.perms)
			if !ok || got != tc.want {
				t.Errorf("resolve = %+v, %v, want %+v", got, ok, tc.want)
			}
		})
	}
}

func TestResolveTakesTheZoneOfARelativeNameFromThePermissions(t *testing.T) {
	patch := func(zone string, names ...string) *dnsgatev1.Permission {
		return &dnsgatev1.Permission{Verbs: []string{"patch"}, Zones: []string{zone}, Names: names, Types: []string{"TXT"}}
	}

	for name, tc := range map[string]struct {
		target Target
		perms  []*dnsgatev1.Permission
		want   Target
		ok     bool
	}{
		"the one zone allowed": {
			target: Target{Name: "_acme-challenge"},
			perms:  []*dnsgatev1.Permission{patch("Example.com.", "_acme-challenge")},
			want:   Target{Zone: "example.com", Name: "_acme-challenge"},
			ok:     true,
		},
		"not a zone where the name is not allowed": {
			target: Target{Name: "_acme-challenge"},
			perms:  []*dnsgatev1.Permission{patch("example.com", "_acme-challenge"), patch("example.net", "www")},
			want:   Target{Zone: "example.com", Name: "_acme-challenge"},
			ok:     true,
		},
		"an absolute match first": {
			target: Target{Name: "_acme-challenge.example.com"},
			perms:  []*dnsgatev1.Permission{patch("example.net", "**"), patch("example.com", "_acme-challenge")},
			want:   Target{Zone: "example.com", Name: "_acme-challenge"},
			ok:     true,
		},
		"no zone for more than one": {
			target: Target{Name: "_acme-challenge"},
			perms:  []*dnsgatev1.Permission{patch("example.com", "_acme-challenge"), patch("example.net", "_acme-challenge")},
		},
		"not relative with a trailing dot": {
			target: Target{Name: "_acme-challenge."},
			perms:  []*dnsgatev1.Permission{patch("example.com", "**")},
		},
		"not relative with a dot, so an absolute name stays out of another zone": {
			target: Target{Name: "_acme-challenge.example.org"},
			perms:  []*dnsgatev1.Permission{patch("example.com", "**")},
		},
		"none for a star zone": {
			target: Target{Name: "_acme-challenge"},
			perms:  []*dnsgatev1.Permission{patch("*", "_acme-challenge")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.target.resolve(tc.perms)
			if ok != tc.ok || got != tc.want {
				t.Errorf("resolve = %+v, %v, want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestDomainTargetResolvesInTheZoneOfTheDomain(t *testing.T) {
	perms := []*dnsgatev1.Permission{{
		Verbs: []string{"patch"}, Zones: []string{"example.com"},
		Names: []string{"_acme-challenge", "_acme-challenge.**"}, Types: []string{"TXT"},
	}}

	for subdomain, want := range map[string]Target{
		"example.com":                          {Zone: "example.com", Name: "_acme-challenge"},
		"Acme.Dev.Example.com.":                {Zone: "example.com", Name: "_acme-challenge.acme.dev"},
		"*.dev.example.com":                    {Zone: "example.com", Name: "_acme-challenge.dev"},
		"_acme-challenge.acme.dev.example.com": {Zone: "example.com", Name: "_acme-challenge.acme.dev"},
		"default":                              {Zone: "example.com", Name: "_acme-challenge"},
	} {
		t.Run(subdomain, func(t *testing.T) {
			target, ok := domainTarget(subdomain)
			if !ok {
				t.Fatalf("domainTarget(%q) refused it", subdomain)
			}

			got, ok := target.resolve(perms)
			if !ok || got != want {
				t.Errorf("resolve = %+v, %v, want %+v", got, ok, want)
			}
		})
	}

	target, _ := domainTarget("www.example.net")
	if got, ok := target.resolve(perms); ok {
		t.Errorf("resolve of a domain in no zone of the token = %+v, want none", got)
	}
}
