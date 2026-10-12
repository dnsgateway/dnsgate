package acme

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"sigs.k8s.io/yaml"

	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// Target is a Challenge Target: the zone, and the record name relative to
// it, where the TXT challenge values of an acme-dns subdomain are added.
// A Target without a zone names its record by its absolute name instead,
// and takes the zone from the token of each update (resolve).
type Target struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
}

// ChallengeMap maps each acme-dns subdomain to its Challenge Target. It
// grants nothing: the Gateway accepts a write only if the token's
// Permissions cover the Challenge Target.
type ChallengeMap map[string]Target

// LoadChallengeMap reads the Challenge Map in file, YAML or JSON, and
// checks each entry: its key must be a single DNS label, and its value
// must name a name, absolute when it names no zone.
func LoadChallengeMap(file string) (ChallengeMap, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading Challenge Map: %w", err)
	}

	var m ChallengeMap
	if err := yaml.UnmarshalStrict(data, &m); err != nil {
		return nil, fmt.Errorf("parsing Challenge Map %s: %w", file, err)
	}

	if err := m.check(); err != nil {
		return nil, fmt.Errorf("invalid Challenge Map %s: %w", file, err)
	}

	return m, nil
}

// check returns the faults of the entries of m, in key order, or nil.
func (m ChallengeMap) check() error {
	var errs []error

	for _, sub := range slices.Sorted(maps.Keys(m)) {
		t := m[sub]

		if !isLabel(sub) {
			errs = append(errs, fmt.Errorf("subdomain %q is not a single DNS label of [A-Za-z0-9-], at most 63 characters, not starting or ending with a hyphen", sub))
		}

		switch {
		case t.Name == "":
			errs = append(errs, fmt.Errorf("subdomain %q has no name", sub))
		case t.Zone == "" && t.Name == dnsname.Apex:
			errs = append(errs, fmt.Errorf("subdomain %q has no zone, so its name must be absolute, not %q", sub, dnsname.Apex))
		}
	}

	return errors.Join(errs...)
}

// resolve returns t with its zone, if the Challenge Map left it out,
// taken from perms, the Permissions of the token that writes it: the
// longest zone a Permission names that holds the absolute t.Name and where
// perms allow patching TXT at it, with t.Name made relative to that zone.
// It reports false if perms name no such zone; a "*" zones entry names
// none. The Gateway still checks the write.
func (t Target) resolve(perms []*dnsgatev1.Permission) (Target, bool) {
	if t.Zone != "" {
		return t, true
	}

	tp := permission.FromAPI(perms)

	var best Target

	for _, p := range tp {
		for _, z := range p.Zones {
			zone := dnsname.Zone(z)

			name, ok := dnsname.Relative(zone, t.Name)
			if !ok || len(zone) <= len(best.Zone) {
				continue
			}

			if permission.Allows(tp, permission.Request{
				Verb: permission.VerbPatch, Resource: permission.ResourceRecords,
				Zone: zone, Name: name, Type: "TXT",
			}) {
				best = Target{Zone: zone, Name: name}
			}
		}
	}

	return best, best.Zone != ""
}
