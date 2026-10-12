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
