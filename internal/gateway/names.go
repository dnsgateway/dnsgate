package gateway

import (
	"strings"

	"github.com/dnsgateway/dnsgate/internal/permission"
)

const (
	maxNameLength  = 253
	maxLabelLength = 63
	maxTypeLength  = 16
)

// checkZone returns a zone name as the Gateway compares it, in lower case
// without a trailing dot, or an invalid request error.
func checkZone(name string) (string, error) {
	zone := permission.ZoneName(name)
	if !validLabels(zone, false) {
		return "", invalidRequest("invalid zone name")
	}

	return zone, nil
}

// checkRecordName returns a zone-relative record name in lower case, or
// an invalid request error. The apex is "@"; a name with a trailing dot is
// absolute, not relative, and refused. A label may be "*", the name of a
// wildcard record.
func checkRecordName(name string) (string, error) {
	name = strings.ToLower(name)
	if name != permission.Apex && !validLabels(name, true) {
		return "", invalidRequest("invalid record name: give it relative to the zone, @ for the zone itself")
	}

	return name, nil
}

// checkType returns a record type in upper case, or an invalid request
// error.
func checkType(typ string) (string, error) {
	typ = strings.ToUpper(typ)

	valid := typ != "" && len(typ) <= maxTypeLength && strings.IndexFunc(typ, func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	}) < 0
	if !valid {
		return "", invalidRequest("invalid record type")
	}

	return typ, nil
}

// validLabels reports whether name is a dot-separated list of labels of
// letters, digits, hyphens and underscores, and, if star, "*" labels.
func validLabels(name string, star bool) bool {
	if name == "" || len(name) > maxNameLength {
		return false
	}

	for label := range strings.SplitSeq(name, ".") {
		if label == "*" && star {
			continue
		}

		if label == "" || len(label) > maxLabelLength || strings.IndexFunc(label, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_'
		}) >= 0 {
			return false
		}
	}

	return true
}

// absoluteName returns the absolute name of a record name relative to
// zone.
func absoluteName(zone, name string) string {
	if name == permission.Apex {
		return zone
	}

	return name + "." + zone
}

// relativeName returns the name of a Provider's record relative to zone,
// and whether the record is in the zone at all.
func relativeName(zone, absolute string) (string, bool) {
	absolute = permission.ZoneName(absolute)
	if absolute == zone {
		return permission.Apex, true
	}

	name, ok := strings.CutSuffix(absolute, "."+zone)

	return name, ok && name != ""
}
