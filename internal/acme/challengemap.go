package acme

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"sigs.k8s.io/yaml"
)

// Target is a Challenge Target: the zone, and the record name relative to
// it, where the TXT challenge values of an acme-dns subdomain are added.
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
// must name both a zone and a name.
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

		if t.Zone == "" {
			errs = append(errs, fmt.Errorf("subdomain %q has no zone", sub))
		}

		if t.Name == "" {
			errs = append(errs, fmt.Errorf("subdomain %q has no name", sub))
		}
	}

	return errors.Join(errs...)
}
