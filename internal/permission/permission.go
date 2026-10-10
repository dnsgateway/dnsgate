// Package permission decides what a Service Token's Permissions allow.
//
// Permissions follow the Kubernetes RBAC style: each rule grants verbs on
// resources, limited by the zones, names, types and egress filters. Rules
// only add up: a request is allowed if any rule allows it.
package permission

import (
	"errors"
	"slices"
	"strings"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// Verb is what a request does, as a rule's verbs name it.
type Verb string

// Verbs.
const (
	VerbGet    Verb = "get"
	VerbList   Verb = "list"
	VerbCreate Verb = "create"
	VerbUpdate Verb = "update"
	VerbPatch  Verb = "patch"
	VerbDelete Verb = "delete"
)

// verbs are the known Verbs.
var verbs = []Verb{VerbGet, VerbList, VerbCreate, VerbUpdate, VerbPatch, VerbDelete}

// Resource is what a request is about, as a rule's resources name it.
type Resource string

// Resources.
const (
	ResourceZones   Resource = "zones"
	ResourceRecords Resource = "records"
	ResourceTokens  Resource = "tokens"
)

// resources are the known Resources.
var resources = []Resource{ResourceZones, ResourceRecords, ResourceTokens}

// Egress is where the connection to the Provider leaves from, as a rule's
// egress filter names it. The empty Egress is none in particular.
type Egress string

// Egress values.
const (
	EgressGateway Egress = "gateway"
	EgressAgent   Egress = "agent"
)

// egresses are the known Egress values, in the order ChooseEgress prefers
// them.
var egresses = []Egress{EgressGateway, EgressAgent}

// apiEgress maps each Egress to the API's.
var apiEgress = map[Egress]dnsgatev1.Egress{
	"":            dnsgatev1.Egress_EGRESS_UNSPECIFIED,
	EgressGateway: dnsgatev1.Egress_EGRESS_GATEWAY,
	EgressAgent:   dnsgatev1.Egress_EGRESS_AGENT,
}

// API returns the API's Egress for e, EGRESS_UNSPECIFIED for the empty
// one, and whether e is known.
func (e Egress) API() (dnsgatev1.Egress, bool) {
	a, ok := apiEgress[e]

	return a, ok
}

// EgressFromAPI returns the Egress the API's a names, empty for
// EGRESS_UNSPECIFIED, and whether a is known.
func EgressFromAPI(a dnsgatev1.Egress) (Egress, bool) {
	for e, v := range apiEgress {
		if v == a {
			return e, true
		}
	}

	return "", false
}

// FromAPI returns the API's Permissions as a token's.
func FromAPI(perms []*dnsgatev1.Permission) []token.Permission {
	out := make([]token.Permission, 0, len(perms))

	for _, p := range perms {
		out = append(out, token.Permission{
			Verbs:     p.GetVerbs(),
			Resources: p.GetResources(),
			Zones:     p.GetZones(),
			Names:     p.GetNames(),
			Types:     p.GetTypes(),
			Egress:    p.GetEgress(),
		})
	}

	return out
}

// ToAPI returns a token's Permission as the API's.
func ToAPI(p token.Permission) *dnsgatev1.Permission {
	return &dnsgatev1.Permission{
		Verbs:     p.Verbs,
		Resources: p.Resources,
		Zones:     p.Zones,
		Names:     p.Names,
		Types:     p.Types,
		Egress:    p.Egress,
	}
}

// Check returns an error for the first malformed rule of perms: one
// without verbs, naming an unknown verb, resource or egress, or holding an
// empty zone, type or name, or a name with an empty label or "@" among
// other labels. Its message never quotes the rule: it may come from a
// client.
func Check(perms []token.Permission) error {
	for _, p := range perms {
		switch {
		case len(p.Verbs) == 0:
			return errors.New("a permission has no verbs")
		case !allKnown(p.Verbs, verbs):
			return errors.New("a permission names an unknown verb")
		case !allKnown(p.Resources, resources):
			return errors.New("a permission names an unknown resource")
		case !allKnown(p.Egress, egresses):
			return errors.New("a permission names an unknown egress")
		case slices.Contains(p.Zones, ""):
			return errors.New("a permission names an empty zone")
		case slices.Contains(p.Types, ""):
			return errors.New("a permission names an empty type")
		case slices.ContainsFunc(p.Names, func(n string) bool { return !validName(n) }):
			return errors.New("a permission names a malformed name pattern")
		}
	}

	return nil
}

// asStrings returns values as strings.
func asStrings[T ~string](values []T) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, string(v))
	}

	return out
}

// allKnown reports whether every value is one of known.
func allKnown[T ~string](values []string, known []T) bool {
	return !slices.ContainsFunc(values, func(v string) bool { return !slices.Contains(known, T(v)) })
}

// validName reports whether a name pattern is the apex, or labels none of
// which is empty or the apex.
func validName(pattern string) bool {
	if pattern == dnsname.Apex {
		return true
	}

	labels := strings.Split(pattern, ".")

	return !slices.Contains(labels, "") && !slices.Contains(labels, dnsname.Apex)
}

// wildcard is the zones and types filter entry that matches every value.
const wildcard = "*"

// Request is what a request asks to do, as Permissions see it.
//
// Zone, Name and Type are left empty for a request that is not about one
// zone, record name or type, such as listing zones or listing a zone's
// records: that filter is not checked then, and the caller filters what
// it returns with a request per zone or record. An empty Egress is not checked
// either; ChooseEgress chooses one for a request that does not ask.
type Request struct {
	Verb     Verb
	Resource Resource
	// Zone is the zone's name, such as "example.com".
	Zone string
	// Name is the record name relative to Zone: dnsname.Apex for the
	// zone's own name, "www.apps" for www.apps.example.com.
	Name   string
	Type   string
	Egress Egress
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
func ChooseEgress(perms []token.Permission, r Request) (Egress, bool) {
	choices := egresses
	if r.Egress != "" {
		choices = []Egress{r.Egress}
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
	return slices.Contains(p.Verbs, string(r.Verb)) &&
		slices.Contains(orDefault(p.Resources, string(ResourceRecords)), string(r.Resource)) &&
		(r.Zone == "" || matchAny(p.Zones, r.Zone, matchZone)) &&
		(r.Name == "" || matchAny(p.Names, r.Name, MatchName)) &&
		(r.Type == "" || matchAny(p.Types, r.Type, matchType)) &&
		(r.Egress == "" || matchAny(p.Egress, string(r.Egress), matchEgress))
}

// orDefault returns filter, or def if filter was left out.
func orDefault(filter []string, def ...string) []string {
	if len(filter) == 0 {
		return def
	}

	return filter
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
	return entry == wildcard || dnsname.Zone(entry) == dnsname.Zone(zone)
}

// matchEgress matches an Egress against an egress filter entry.
func matchEgress(entry, egress string) bool {
	return entry == egress
}

// matchType matches a record type against a types filter entry: "*" or a
// type, ignoring case.
func matchType(entry, typ string) bool {
	return entry == wildcard || strings.EqualFold(entry, typ)
}

// Name pattern wildcards.
const (
	// AnyLabel matches exactly one label.
	AnyLabel = "*"
	// AnyLabels matches one or more labels.
	AnyLabels = "**"
)

// MatchName reports whether the zone-relative record name matches the
// name pattern, ignoring case. The apex, dnsname.Apex, matches only
// itself, and neither
// wildcard matches it: "*.apps" matches "www.apps" but not "apps".
func MatchName(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)

	if pattern == dnsname.Apex || name == dnsname.Apex {
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
