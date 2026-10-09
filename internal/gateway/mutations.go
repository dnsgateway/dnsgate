package gateway

import (
	"strings"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// Each record verb becomes one Changeset, applied through the Provider:
// the Gateway reads the RRset, works out the records it should hold, and
// changes the one into the other with as few changes as it can.

// recordRequest is a record mutation: it names a zone, a record name and
// a type.
type recordRequest interface {
	tokenRequest
	GetZone() string
	GetName() string
	GetType() string
}

// startMutation takes a record mutation through the Gateway's checks, as
// startDNSCall does, for verb on its zone, name and type.
func (g *Gateway) startMutation(r *request, event audit.Name, verb permission.Verb, req recordRequest) (*dnsCall, error) {
	return g.startDNSCall(r, event, req, permission.Request{
		Verb: verb, Resource: permission.ResourceRecords, Zone: req.GetZone(), Name: req.GetName(), Type: req.GetType(),
	}, checkRecordOf)
}

// createRecord creates an RRset the zone does not hold yet. The token
// needs create on records for its zone, name and type.
func (g *Gateway) createRecord(r *request, req *dnsgatev1.CreateRecordRequest) (*dnsgatev1.Response, error) {
	c, err := g.startMutation(r, audit.EventRecordsCreate, permission.VerbCreate, req)
	if err != nil {
		return nil, err
	}

	target, err := g.checkRecords(c, req.GetTtl(), req.GetValues())
	if err != nil {
		return nil, err
	}

	zone, current, err := g.readRRset(c)
	if err != nil {
		return nil, err
	}

	if len(current) > 0 {
		return nil, g.fail(c, alreadyExists("the record set already exists: update or patch it"))
	}

	set, err := g.apply(c, zone, current, target)
	if err != nil {
		return nil, err
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_CreateRecord{
		CreateRecord: &dnsgatev1.CreateRecordResponse{RecordSet: set},
	}}, nil
}

// updateRecord replaces every record of an RRset the zone holds with the
// request's values. The token needs update on records for its zone, name
// and type.
func (g *Gateway) updateRecord(r *request, req *dnsgatev1.UpdateRecordRequest) (*dnsgatev1.Response, error) {
	c, err := g.startMutation(r, audit.EventRecordsUpdate, permission.VerbUpdate, req)
	if err != nil {
		return nil, err
	}

	target, err := g.checkRecords(c, req.GetTtl(), req.GetValues())
	if err != nil {
		return nil, err
	}

	zone, current, err := g.readRRset(c)
	if err != nil {
		return nil, err
	}

	if len(current) == 0 {
		return nil, g.fail(c, notFound("no such record set: create it"))
	}

	set, err := g.apply(c, zone, current, target)
	if err != nil {
		return nil, err
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_UpdateRecord{
		UpdateRecord: &dnsgatev1.UpdateRecordResponse{RecordSet: set},
	}}, nil
}

// checkRecords checks the TTL and values of a create or update and
// returns the records they make of the call's RRset. A refused request is
// audited as denied.
func (g *Gateway) checkRecords(c *dnsCall, ttl uint32, values []string) ([]dnsprovider.Record, error) {
	if len(values) == 0 {
		return nil, g.deny(c.request, c.event, invalidRequest("no values: a record set holds at least one"))
	}

	if err := g.checkValues(c, values); err != nil {
		return nil, err
	}

	if err := g.checkTTL(c, ttl); err != nil {
		return nil, err
	}

	return c.records(ttl, values), nil
}

// checkValues checks that each value is given once and is in the form
// the call's record type takes.
func (g *Gateway) checkValues(c *dnsCall, values []string) error {
	typ := c.perm.Type
	if !dnsprovider.Editable(typ) {
		return g.deny(c.request, c.event, invalidRecord("records of this type cannot be changed through the gateway"))
	}

	seen := make(map[string]bool, len(values))

	for _, v := range values {
		if seen[v] {
			return g.deny(c.request, c.event, invalidRequest("a value is given twice"))
		}

		seen[v] = true

		if err := dnsprovider.CheckValue(typ, v); err != nil {
			return g.deny(c.request, c.event, invalidRecord("a value is not in the form its record type takes"))
		}
	}

	return nil
}

// checkTTL checks that ttl is in the range the call's Provider takes.
func (g *Gateway) checkTTL(c *dnsCall, ttl uint32) error {
	if err := dnsprovider.TTLRangeOf(c.provider).Check(ttl); err != nil {
		return g.deny(c.request, c.event, invalidRecord(err.Error()))
	}

	return nil
}

// records returns the records of the call's RRset with ttl and values.
func (c *dnsCall) records(ttl uint32, values []string) []dnsprovider.Record {
	name := dnsname.Absolute(c.perm.Zone, c.perm.Name)

	out := make([]dnsprovider.Record, 0, len(values))
	for _, v := range values {
		out = append(out, dnsprovider.Record{Type: c.perm.Type, Name: name, Value: v, TTL: ttl})
	}

	return out
}

// readRRset reads the call's zone and the records of its RRset.
func (g *Gateway) readRRset(c *dnsCall) (dnsprovider.Zone, []dnsprovider.Record, error) {
	zone, name, typ := c.perm.Zone, c.perm.Name, c.perm.Type

	// Contains narrows the Provider's answer to names ending in this one;
	// the exact name is matched below.
	z, records, err := g.readRecords(c, dnsprovider.RecordFilter{Type: typ, Contains: dnsname.Absolute(zone, name) + "."})
	if err != nil {
		return dnsprovider.Zone{}, nil, err
	}

	var rrset []dnsprovider.Record

	for _, rec := range records {
		if n, ok := dnsname.Relative(zone, rec.Name); ok && n == name && strings.EqualFold(rec.Type, typ) {
			rrset = append(rrset, rec)
		}
	}

	return z, rrset, nil
}

// apply changes the records current of the call's RRset into target,
// through one Changeset, and audits the call. It returns the RRset as the
// Provider holds it after, nil when it holds none. When the Provider
// fails a change, the call fails; the changes it confirmed stay made.
func (g *Gateway) apply(c *dnsCall, zone dnsprovider.Zone, current, target []dnsprovider.Record) (*dnsgatev1.RecordSet, error) {
	changes, kept := plan(current, target)

	after := kept

	if len(changes) > 0 {
		res, err := dnsprovider.Apply(c.ctx, c.provider, dnsprovider.Changeset{Zone: zone, Changes: changes})
		if err != nil {
			return nil, g.providerFailed(c, err)
		}

		for _, r := range res.Results {
			if r.Err != nil {
				return nil, g.providerFailed(c, r.Err)
			}

			if r.Change.Kind == dnsprovider.ChangeDelete {
				continue
			}

			rec := r.Record
			if rec.Type == "" {
				rec = r.Change.After
			}

			after = append(after, rec)
		}
	}

	g.succeed(c)

	sets := recordSets(c.perm.Zone, after, func(string, string) bool { return true })
	if len(sets) == 0 {
		return nil, nil //nolint:nilnil // an RRset the change emptied
	}

	return sets[0], nil
}

// plan returns the changes that turn the records current of an RRset into
// target, and the records of current it leaves as they are. A record of
// current is kept for the target record of its value, its TTL modified if
// it differs; each other one is modified into a target record no record
// holds the value of, while there are some, and deleted after. The
// target records left are added. Modifying rather than deleting and
// adding keeps the RRset from going empty while it is replaced.
func plan(current, target []dnsprovider.Record) (changes []dnsprovider.Change, kept []dnsprovider.Record) {
	used := make([]bool, len(current))

	var unheld []dnsprovider.Record

	for _, t := range target {
		i := -1

		for j, rec := range current {
			if !used[j] && rec.Value == t.Value {
				i = j

				break
			}
		}

		if i < 0 {
			unheld = append(unheld, t)

			continue
		}

		used[i] = true

		if current[i].TTL == t.TTL {
			kept = append(kept, current[i])

			continue
		}

		after := current[i]
		after.TTL = t.TTL
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: current[i], After: after})
	}

	for j, rec := range current {
		if used[j] {
			continue
		}

		if len(unheld) == 0 {
			changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: rec})

			continue
		}

		after := rec
		after.Value, after.TTL = unheld[0].Value, unheld[0].TTL
		unheld = unheld[1:]
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: rec, After: after})
	}

	for _, t := range unheld {
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: t})
	}

	return changes, kept
}
