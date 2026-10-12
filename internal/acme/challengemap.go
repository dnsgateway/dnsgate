package acme

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"sigs.k8s.io/yaml"

	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// Target is a Challenge Target: the zone, and the record name relative to
// it, where the TXT challenge values of an acme-dns subdomain are added.
// A Target without a zone takes the zone from the token of each update
// (resolve): its name is absolute, or a single label in the one zone the
// token allows.
type Target struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
}

// ChallengeMap maps each acme-dns subdomain to its Challenge Target. It
// grants nothing: the Gateway accepts a write only if the token's
// Permissions cover the Challenge Target.
type ChallengeMap map[string]Target

// challengeLabel is the label ACME DNS-01 puts in front of the domain.
const challengeLabel = "_acme-challenge"

// maxDomainLen is the longest domain name, in presentation form without
// the trailing dot.
const maxDomainLen = 253

// domainTarget returns the Challenge Target, without a zone, of a
// subdomain not in the Challenge Map, and whether the subdomain is a
// single DNS label or a domain name at all. A domain is taken as the
// certificate domain, its Challenge Target _acme-challenge in front of it
// as an absolute name, so resolve takes the longest zone of the token
// that holds it; a leading "*." or _acme-challenge label is dropped, case
// and a trailing dot are ignored. A single label names _acme-challenge in
// the one zone the token allows.
func domainTarget(subdomain string) (Target, bool) {
	if isLabel(subdomain) {
		return Target{Name: challengeLabel}, true
	}

	domain := dnsname.Zone(subdomain)
	if len(domain) > maxDomainLen || !strings.Contains(domain, ".") {
		return Target{}, false
	}

	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, challengeLabel+".")

	if slices.ContainsFunc(strings.Split(domain, "."), func(l string) bool { return !isLabel(l) }) {
		return Target{}, false
	}

	return Target{Name: challengeLabel + "." + domain + "."}, true
}

// LoadChallengeMap reads the Challenge Map in file, YAML or JSON, and
// checks each entry: its key must be a single DNS label, and its value
// must name a name, not the apex when it names no zone.
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
			errs = append(errs, fmt.Errorf("subdomain %q has no zone, so its name cannot be %q", sub, dnsname.Apex))
		}
	}

	return errors.Join(errs...)
}

// resolve returns t with its zone, if the Challenge Map left it out,
// taken from perms, the Permissions of the token that writes it. First as
// an absolute name: the longest zone a Permission names that holds t.Name
// and where perms allow patching TXT at it, with t.Name made relative to
// that zone. Failing that, if t.Name is a single label, as a name in any
// zone: the one zone a Permission names where perms allow patching TXT at
// t.Name. A name with a dot is never read as relative, so an absolute name
// in no zone of the token cannot land in another. It reports false if
// perms name no such zone, or more than one for a single label; a "*"
// zones entry names none. The Gateway still checks the write.
func (t Target) resolve(perms []*dnsgatev1.Permission) (Target, bool) {
	if t.Zone != "" {
		return t, true
	}

	tp := permission.FromAPI(perms)

	allows := func(zone, name string) bool {
		return permission.Allows(tp, permission.Request{
			Verb: permission.VerbPatch, Resource: permission.ResourceRecords,
			Zone: zone, Name: name, Type: "TXT",
		})
	}

	var (
		best          Target
		relativeZones []string
	)

	for _, p := range tp {
		for _, z := range p.Zones {
			// A "*" zones entry names no zone.
			zone := dnsname.Zone(z)
			if zone == "*" {
				continue
			}

			if name, ok := dnsname.Relative(zone, t.Name); ok {
				if len(zone) > len(best.Zone) && allows(zone, name) {
					best = Target{Zone: zone, Name: name}
				}
			} else if !strings.Contains(t.Name, ".") && allows(zone, t.Name) {
				relativeZones = append(relativeZones, zone)
			}
		}
	}

	if best.Zone != "" {
		return best, true
	}

	slices.Sort(relativeZones)
	if relativeZones = slices.Compact(relativeZones); len(relativeZones) != 1 {
		return Target{}, false
	}

	return Target{Zone: relativeZones[0], Name: t.Name}, true
}
