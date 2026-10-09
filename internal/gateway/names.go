package gateway

import (
	"cmp"
	"strings"

	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

const (
	maxNameLength  = 253
	maxLabelLength = 63
	maxTypeLength  = 16
)

// checkZoneOf checks the zone of pr and puts it in the form the Gateway
// compares, or empties it if it fails.
func checkZoneOf(pr *permission.Request) error {
	zone, err := checkZone(pr.Zone)
	pr.Zone = zone

	return err
}

// checkRecordOf checks the zone, record name and type of pr and puts them
// in the form the Gateway compares. Each that fails its check is emptied,
// and the error is that of the first.
func checkRecordOf(pr *permission.Request) error {
	zoneErr := checkZoneOf(pr)
	name, nameErr := checkRecordName(pr.Name)
	typ, typeErr := checkType(pr.Type)

	pr.Name, pr.Type = name, typ

	return cmp.Or(zoneErr, nameErr, typeErr)
}

// checkZone returns a zone name as the Gateway compares it, in lower case
// without a trailing dot, or an invalid request error.
func checkZone(name string) (string, error) {
	zone := dnsname.Zone(name)
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
	if name != dnsname.Apex && !validLabels(name, true) {
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
