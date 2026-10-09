package permission

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsgate/internal/dnsname"
)

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
