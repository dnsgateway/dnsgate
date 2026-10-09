// Package dnsname puts zone and record names in the form the Gateway
// compares them: zone names in lower case without a trailing dot, record
// names relative to their zone.
package dnsname

import "strings"

// Apex is the name of a zone's own name, relative to the zone.
const Apex = "@"

// Zone returns a zone name in lower case, without a trailing dot.
func Zone(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Absolute returns the absolute name of a record name relative to zone.
func Absolute(zone, name string) string {
	if name == Apex {
		return zone
	}

	return name + "." + zone
}

// Relative returns the name of a record, given absolute, relative to
// zone, and whether the record is in the zone at all.
func Relative(zone, absolute string) (string, bool) {
	absolute = Zone(absolute)
	if absolute == zone {
		return Apex, true
	}

	name, ok := strings.CutSuffix(absolute, "."+zone)

	return name, ok && name != ""
}
