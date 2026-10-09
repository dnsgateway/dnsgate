// Package permission decides what a Service Token's Permissions allow.
//
// Permissions follow the Kubernetes RBAC style: each rule grants verbs on
// resources, limited by the zones, names, types and egress filters. Rules
// only add up: a request is allowed if any rule allows it.
package permission

import (
	"slices"
	"strings"

	"github.com/dnsgateway/dnsgate/internal/token"
)

// Verbs.
const (
	VerbGet    = "get"
	VerbList   = "list"
	VerbCreate = "create"
	VerbUpdate = "update"
	VerbPatch  = "patch"
	VerbDelete = "delete"
)

// Resources.
const (
	ResourceZones   = "zones"
	ResourceRecords = "records"
	ResourceTokens  = "tokens"
)

// Egress values.
const (
	EgressGateway = "gateway"
	EgressAgent   = "agent"
)

// Apex is the name of a zone's own name, relative to the zone.
const Apex = "@"

// wildcard is the zones and types filter entry that matches every value.
const wildcard = "*"

// Request is what a request asks to do, as Permissions see it.
//
// Name and Type are left empty for a request that is not about one record
// name or type, such as reading a zone or listing a zone's records: no
// names or types filter is checked then, and the caller filters what it
// returns with a request per record. An empty Egress is not checked
// either; ChooseEgress chooses one for a request that does not ask.
type Request struct {
	Verb     string
	Resource string
	// Zone is the zone's name, such as "example.com".
	Zone string
	// Name is the record name relative to Zone: Apex for the zone's own
	// name, "www.apps" for www.apps.example.com.
	Name   string
	Type   string
	Egress string
}

// Allows reports whether any of perms allows r.
func Allows(perms []token.Permission, r Request) bool {
	return slices.ContainsFunc(perms, func(p token.Permission) bool { return allows(p, r) })
}

// ChooseEgress returns the Egress r goes through and whether perms allow
// r through it. An Egress r asks for is the only one it may go through.
// Left to choose, it is Gateway Egress where a rule allows it, else Agent
// Egress: a token limited to Agent Egress never falls back to Gateway
// Egress.
func ChooseEgress(perms []token.Permission, r Request) (string, bool) {
	choices := []string{EgressGateway, EgressAgent}
	if r.Egress != "" {
		choices = []string{r.Egress}
	}

	for _, e := range choices {
		r.Egress = e
		if Allows(perms, r) {
			return e, true
		}
	}

	return "", false
}

// allows reports whether the one rule p allows r. A filter left out, nil
// or empty, takes its default: resources ["records"], any zone, name, type
// and egress. Verbs have no default: a rule without them grants nothing.
func allows(p token.Permission, r Request) bool {
	resources := p.Resources
	if len(resources) == 0 {
		resources = []string{ResourceRecords}
	}

	return slices.Contains(p.Verbs, r.Verb) &&
		slices.Contains(resources, r.Resource) &&
		matchAny(p.Zones, r.Zone, matchZone) &&
		(r.Name == "" || matchAny(p.Names, r.Name, MatchName)) &&
		(r.Type == "" || matchAny(p.Types, r.Type, matchType)) &&
		(r.Egress == "" || matchAny(p.Egress, r.Egress, func(e, v string) bool { return e == v }))
}

// matchAny reports whether value matches any entry of filter, or filter
// was left out.
func matchAny(filter []string, value string, match func(entry, value string) bool) bool {
	if len(filter) == 0 {
		return true
	}

	return slices.ContainsFunc(filter, func(entry string) bool { return match(entry, value) })
}

// matchZone matches a zone name against a zones filter entry: "*" or an
// exact zone name, ignoring case and a trailing dot.
func matchZone(entry, zone string) bool {
	return entry == wildcard || zoneName(entry) == zoneName(zone)
}

// matchType matches a record type against a types filter entry: "*" or a
// type, ignoring case.
func matchType(entry, typ string) bool {
	return entry == wildcard || strings.EqualFold(entry, typ)
}

// zoneName returns a zone name as zones filters compare it: in lower case,
// without a trailing dot.
func zoneName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Name pattern wildcards.
const (
	// AnyLabel matches exactly one label.
	AnyLabel = "*"
	// AnyLabels matches one or more labels.
	AnyLabels = "**"
)

// MatchName reports whether the zone-relative record name matches the
// name pattern, ignoring case. Apex matches only itself, and neither
// wildcard matches it: "*.apps" matches "www.apps" but not "apps".
func MatchName(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)

	if pattern == Apex || name == Apex {
		return pattern == name
	}

	return matchLabels(strings.Split(pattern, "."), strings.Split(name, "."))
}

// matchLabels matches name labels against pattern labels, left to right.
func matchLabels(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}

	if len(name) == 0 {
		return false
	}

	switch pattern[0] {
	case AnyLabels:
		// Take one label, then either stop taking or take more.
		return matchLabels(pattern[1:], name[1:]) || matchLabels(pattern, name[1:])
	case AnyLabel:
		return matchLabels(pattern[1:], name[1:])
	default:
		return pattern[0] == name[0] && matchLabels(pattern[1:], name[1:])
	}
}
