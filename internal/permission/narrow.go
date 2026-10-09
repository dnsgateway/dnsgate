package permission

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/token"
)

// Dimension is a part of a Permission, as Narrowing names what exceeds a
// Parent Token's Permissions.
type Dimension string

// Permission dimensions, in the order Covers checks them.
const (
	DimensionVerbs     Dimension = "verbs"
	DimensionResources Dimension = "resources"
	DimensionEgress    Dimension = "egress"
	DimensionZones     Dimension = "zones"
	DimensionTypes     Dimension = "types"
	DimensionNames     Dimension = "names"
)

// Covers reports whether the parent Permissions allow everything the child
// Permissions do, and if not, the first Dimension where a child rule
// exceeds them.
//
// A filter left out means its default, in the child as in the parent:
// resources ["records"], any zone, name, type and egress. A child's
// "any" is covered only by a parent's "any", whether the parent left the
// filter out or spelled it ("*", or names "@" and "**").
//
// Each combination of a child rule's verb, resource, egress, zone entry
// and type entry must be allowed by one parent rule, since a parent rule
// allows only the combinations of its own entries. Its name patterns may
// be covered by the name patterns of all those rules together.
func Covers(parent, child []token.Permission) (Dimension, bool) {
	for _, c := range child {
		if d, ok := coversRule(parent, c); !ok {
			return d, false
		}
	}

	return "", true
}

// allNames is the names filter that is left out.
var allNames = []string{dnsname.Apex, AnyLabels}

func coversRule(parent []token.Permission, c token.Permission) (Dimension, bool) {
	resources := orDefault(c.Resources, string(ResourceRecords))
	egress := orDefault(c.Egress, string(EgressGateway), string(EgressAgent))
	zones := orDefault(c.Zones, wildcard)
	types := orDefault(c.Types, wildcard)
	names := orDefault(c.Names, allNames...)

	for _, verb := range c.Verbs {
		for _, res := range resources {
			for _, e := range egress {
				for _, zone := range zones {
					for _, typ := range types {
						if d, ok := coversEntries(parent, verb, res, e, zone, typ, names); !ok {
							return d, false
						}
					}
				}
			}
		}
	}

	return "", true
}

// coversEntries reports whether the parent rules allow names under one
// verb, resource, egress, zone entry and type entry of a child rule, and
// if not, which dimension none of them allows.
func coversEntries(parent []token.Permission, verb, res, egress, zone, typ string, names []string) (Dimension, bool) {
	steps := []struct {
		dim   Dimension
		allow func(token.Permission) bool
	}{
		{DimensionVerbs, func(p token.Permission) bool { return slices.Contains(p.Verbs, verb) }},
		{DimensionResources, func(p token.Permission) bool {
			return slices.Contains(orDefault(p.Resources, string(ResourceRecords)), res)
		}},
		{DimensionEgress, func(p token.Permission) bool {
			return matchAny(p.Egress, egress, func(e, v string) bool { return e == v })
		}},
		{DimensionZones, func(p token.Permission) bool { return matchAny(p.Zones, zone, matchZone) }},
		{DimensionTypes, func(p token.Permission) bool { return matchAny(p.Types, typ, matchType) }},
	}

	rules := parent
	for _, s := range steps {
		rules = slices.DeleteFunc(slices.Clone(rules), func(p token.Permission) bool { return !s.allow(p) })
		if len(rules) == 0 {
			return s.dim, false
		}
	}

	var patterns []string
	for _, p := range rules {
		patterns = append(patterns, orDefault(p.Names, allNames...)...)
	}

	for _, n := range names {
		if !CoversName(patterns, n) {
			return DimensionNames, false
		}
	}

	return "", true
}

// orDefault returns filter, or def if filter was left out.
func orDefault(filter []string, def ...string) []string {
	if len(filter) == 0 {
		return def
	}

	return filter
}

// CoversName reports whether every record name the name pattern child
// matches is matched by one of patterns, ignoring case. The patterns may
// cover child only together: "*" and "*.**" cover "**".
//
// It decides this exactly. A pattern is a regular language over labels,
// and a label no pattern names literally is matched by the same wildcards
// as any other such label, so following the labels the patterns name, plus
// one they do not, is enough. Every name child may take is followed
// through all patterns at once, until child ends where none of them does.
func CoversName(patterns []string, child string) bool {
	c := nameLabels(child)

	ps := make([][]string, 0, len(patterns))
	for _, p := range patterns {
		ps = append(ps, nameLabels(p))
	}

	alphabet := labelAlphabet(append([][]string{c}, ps...))

	start := make(patternSet, 0, len(ps))
	for i := range ps {
		start = append(start, patternPos{i, 0})
	}

	type state struct {
		pos int
		set patternSet
	}

	seen := map[string]bool{}
	queue := []state{{0, start}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if cur.pos == len(c) && !cur.set.accepts(ps) {
			return false
		}

		for _, label := range alphabet {
			next := cur.set.step(ps, label)

			for _, pos := range stepLabel(c, cur.pos, label) {
				// From any position child can still match a name, so a
				// name no pattern matches.
				if len(next) == 0 {
					return false
				}

				key := strconv.Itoa(pos) + "|" + next.key()
				if !seen[key] {
					seen[key] = true

					queue = append(queue, state{pos, next})
				}
			}
		}
	}

	return true
}

// nameLabels returns the labels of a name pattern in lower case: none for
// the apex.
func nameLabels(pattern string) []string {
	pattern = strings.ToLower(pattern)
	if pattern == dnsname.Apex {
		return nil
	}

	return strings.Split(pattern, ".")
}

// otherLabel stands for every label no pattern names. A record name label
// never holds it.
const otherLabel = "\x00"

// labelAlphabet returns the literal labels of patterns and otherLabel.
func labelAlphabet(patterns [][]string) []string {
	alphabet := []string{otherLabel}

	for _, p := range patterns {
		for _, l := range p {
			if l != AnyLabel && l != AnyLabels && !slices.Contains(alphabet, l) {
				alphabet = append(alphabet, l)
			}
		}
	}

	return alphabet
}

// stepLabel returns the positions in the pattern labels p reached from pos
// by matching label.
func stepLabel(p []string, pos int, label string) []int {
	if pos == len(p) {
		return nil
	}

	switch p[pos] {
	case AnyLabels:
		// Take this label, then either stop taking or take more.
		return []int{pos, pos + 1}
	case AnyLabel, label:
		return []int{pos + 1}
	default:
		return nil
	}
}

// patternPos is a position in one of several patterns.
type patternPos struct{ pattern, pos int }

// patternSet is the positions several patterns may be at, sorted.
type patternSet []patternPos

// step returns the positions s reaches by matching label.
func (s patternSet) step(patterns [][]string, label string) patternSet {
	var next patternSet

	for _, pp := range s {
		for _, pos := range stepLabel(patterns[pp.pattern], pp.pos, label) {
			if np := (patternPos{pp.pattern, pos}); !slices.Contains(next, np) {
				next = append(next, np)
			}
		}
	}

	slices.SortFunc(next, func(a, b patternPos) int {
		return cmp.Or(cmp.Compare(a.pattern, b.pattern), cmp.Compare(a.pos, b.pos))
	})

	return next
}

// accepts reports whether a pattern of s is at its end.
func (s patternSet) accepts(patterns [][]string) bool {
	return slices.ContainsFunc(s, func(pp patternPos) bool { return pp.pos == len(patterns[pp.pattern]) })
}

// key identifies s in a map.
func (s patternSet) key() string {
	var b strings.Builder

	for _, pp := range s {
		b.WriteString(strconv.Itoa(pp.pattern))
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(pp.pos))
		b.WriteByte(',')
	}

	return b.String()
}
