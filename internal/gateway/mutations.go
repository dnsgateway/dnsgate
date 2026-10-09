package gateway

import (
	"cmp"
	"slices"
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
	set, err := g.setRecord(r, audit.EventRecordsCreate, permission.VerbCreate, req, func(current []dnsprovider.Record) error {
		if len(current) > 0 {
			return alreadyExists("the record set already exists: update or patch it")
		}

		return nil
	})
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
	set, err := g.setRecord(r, audit.EventRecordsUpdate, permission.VerbUpdate, req, func(current []dnsprovider.Record) error {
		if len(current) == 0 {
			return notFound("no such record set: create it")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_UpdateRecord{
		UpdateRecord: &dnsgatev1.UpdateRecordResponse{RecordSet: set},
	}}, nil
}

// setRecordRequest is a create or update: it gives every value, and the
// TTL, of the RRset it names.
type setRecordRequest interface {
	recordRequest
	GetTtl() uint32
	GetValues() []string
}

// setRecord makes the RRset req names hold one record per value of req,
// and no other, for verb, and returns it as the Provider holds it after.
// guard refuses, with the error it returns, the RRset the zone holds
// before.
func (g *Gateway) setRecord(
	r *request, event audit.Name, verb permission.Verb, req setRecordRequest, guard func(current []dnsprovider.Record) error,
) (*dnsgatev1.RecordSet, error) {
	c, err := g.startMutation(r, event, verb, req)
	if err != nil {
		return nil, err
	}

	target, err := c.checkRecords(req.GetTtl(), req.GetValues())
	if err != nil {
		return nil, g.fail(c, err)
	}

	zone, current, err := g.readRRset(c)
	if err != nil {
		return nil, err
	}

	if err := guard(current); err != nil {
		return nil, g.fail(c, err)
	}

	return g.apply(c, zone, current, target)
}

// patchRecord adds values to an RRset and removes others, leaving the
// rest of its records as they are. The token needs patch on records for
// its zone, name and type. A value added that the RRset holds and one
// removed that it does not hold change nothing. Values added take the
// request's TTL, or else the RRset's, the lowest of its records'.
func (g *Gateway) patchRecord(r *request, req *dnsgatev1.PatchRecordRequest) (*dnsgatev1.Response, error) {
	c, err := g.startMutation(r, audit.EventRecordsPatch, permission.VerbPatch, req)
	if err != nil {
		return nil, err
	}

	add, remove := req.GetAdd(), req.GetRemove()
	if len(add) == 0 && len(remove) == 0 {
		return nil, g.fail(c, invalidRequest("nothing to add or remove"))
	}

	if err := c.checkValues(slices.Concat(add, remove)); err != nil {
		return nil, g.fail(c, err)
	}

	ttl := req.GetTtl()
	if ttl != 0 {
		if err := c.checkTTL(ttl); err != nil {
			return nil, g.fail(c, err)
		}
	}

	zone, current, err := g.readRRset(c)
	if err != nil {
		return nil, err
	}

	target := slices.DeleteFunc(slices.Clone(current), func(rec dnsprovider.Record) bool { return slices.Contains(remove, rec.Value) })

	added := slices.DeleteFunc(slices.Clone(add), func(v string) bool {
		return slices.ContainsFunc(current, func(rec dnsprovider.Record) bool { return rec.Value == v })
	})
	if len(added) > 0 {
		if ttl == 0 {
			ttl = rrsetTTL(current)
		}

		if ttl == 0 {
			return nil, g.fail(c, invalidRecord("no TTL: give one to create the record set"))
		}

		target = append(target, c.records(ttl, added)...)
	}

	set, err := g.apply(c, zone, current, target)
	if err != nil {
		return nil, err
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_PatchRecord{
		PatchRecord: &dnsgatev1.PatchRecordResponse{RecordSet: set},
	}}, nil
}

// deleteRecord deletes every record of an RRset the zone holds. The token
// needs delete on records for its zone, name and type.
func (g *Gateway) deleteRecord(r *request, req *dnsgatev1.DeleteRecordRequest) (*dnsgatev1.Response, error) {
	c, err := g.startMutation(r, audit.EventRecordsDelete, permission.VerbDelete, req)
	if err != nil {
		return nil, err
	}

	zone, current, err := g.readRRset(c)
	if err != nil {
		return nil, err
	}

	if len(current) == 0 {
		return nil, g.fail(c, notFound("no such record set"))
	}

	if _, err := g.apply(c, zone, current, nil); err != nil {
		return nil, err
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_DeleteRecord{
		DeleteRecord: &dnsgatev1.DeleteRecordResponse{},
	}}, nil
}

// rrsetTTL returns the TTL of an RRset, the lowest of its records', or
// zero for none.
func rrsetTTL(records []dnsprovider.Record) uint32 {
	if len(records) == 0 {
		return 0
	}

	return slices.MinFunc(records, func(a, b dnsprovider.Record) int { return cmp.Compare(a.TTL, b.TTL) }).TTL
}

// checkRecords checks the TTL and values of a create or update and
// returns the records they make of the call's RRset, or the Gateway error
// of the first that is malformed.
func (c *dnsCall) checkRecords(ttl uint32, values []string) ([]dnsprovider.Record, error) {
	if len(values) == 0 {
		return nil, invalidRequest("no values: a record set holds at least one")
	}

	if err := c.checkValues(values); err != nil {
		return nil, err
	}

	if err := c.checkTTL(ttl); err != nil {
		return nil, err
	}

	return c.records(ttl, values), nil
}

// checkValues checks that each value is given once and is in the form
// the call's record type takes.
func (c *dnsCall) checkValues(values []string) error {
	typ := c.perm.Type
	if !dnsprovider.Editable(typ) {
		return invalidRecord("records of this type cannot be changed through the gateway")
	}

	seen := make(map[string]bool, len(values))

	for _, v := range values {
		if seen[v] {
			return invalidRequest("a value is given twice")
		}

		seen[v] = true

		if err := dnsprovider.CheckValue(typ, v); err != nil {
			return invalidRecord("a value is not in the form its record type takes")
		}
	}

	return nil
}

// checkTTL checks that ttl is in the range the call's Provider takes.
func (c *dnsCall) checkTTL(ttl uint32) error {
	if err := dnsprovider.TTLRangeOf(c.provider).Check(ttl); err != nil {
		return invalidRecord(err.Error())
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
// fails a change, the call fails; the changes it confirmed stay made,
// and the audit event counts them either way.
func (g *Gateway) apply(c *dnsCall, zone dnsprovider.Zone, current, target []dnsprovider.Record) (*dnsgatev1.RecordSet, error) {
	changes, kept := plan(current, target)

	after := kept

	applied := 0
	c.event.ChangesApplied = &applied

	if len(changes) > 0 {
		res, err := dnsprovider.Apply(c.ctx, c.provider, dnsprovider.Changeset{Zone: zone, Changes: changes})
		if err != nil {
			return nil, g.providerFailed(c, err)
		}

		var failed error

		for _, r := range res.Results {
			if r.Err != nil {
				failed = cmp.Or(failed, r.Err)

				continue
			}

			applied++

			if r.Change.Kind == dnsprovider.ChangeDelete {
				continue
			}

			rec := r.Record
			if rec.Type == "" {
				rec = r.Change.After
			}

			after = append(after, rec)
		}

		if failed != nil {
			return nil, g.providerFailed(c, failed)
		}
	}

	g.succeed(c)

	sets := recordSets(c.perm.Zone, after, keepAll)
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

	// unmatched are the target records no record of current holds the
	// value of.
	var unmatched []dnsprovider.Record

	for _, t := range target {
		i := -1

		for j, rec := range current {
			if !used[j] && rec.Value == t.Value {
				i = j

				break
			}
		}

		if i < 0 {
			unmatched = append(unmatched, t)

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

		if len(unmatched) == 0 {
			changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: rec})

			continue
		}

		after := rec
		after.Value, after.TTL = unmatched[0].Value, unmatched[0].TTL
		unmatched = unmatched[1:]
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: rec, After: after})
	}

	for _, t := range unmatched {
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: t})
	}

	return changes, kept
}
