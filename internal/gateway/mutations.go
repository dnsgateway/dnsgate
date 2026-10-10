package gateway

import (
	"cmp"
	"maps"
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
			return alreadyExists("the RRset already exists: update or patch it")
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
			return notFound("no such RRset: create it")
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
	GetRecords() []*dnsgatev1.RecordValue
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

	target, err := c.checkRecords(req.GetTtl(), req.GetRecords())
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

	if err := c.checkKeptExtras(current, req.GetRecords()); err != nil {
		return nil, g.fail(c, err)
	}

	return g.apply(c, zone, current, target)
}

// patchRecord adds values to an RRset and removes others, leaving the
// rest of its records as they are. The token needs patch on records for
// its zone, name and type. A value added that the RRset holds changes
// only its Record Extras, and one removed that it does not hold changes
// nothing. Values added take the request's TTL, or else the RRset's, the
// lowest of its records'.
func (g *Gateway) patchRecord(r *request, req *dnsgatev1.PatchRecordRequest) (*dnsgatev1.Response, error) {
	c, err := g.startMutation(r, audit.EventRecordsPatch, permission.VerbPatch, req)
	if err != nil {
		return nil, err
	}

	add, remove := req.GetAdd(), req.GetRemove()
	if len(add) == 0 && len(remove) == 0 {
		return nil, g.fail(c, invalidRequest("nothing to add or remove"))
	}

	if err := c.checkValues(slices.Concat(valuesOf(add), remove)); err != nil {
		return nil, g.fail(c, err)
	}

	if err := c.checkExtras(add); err != nil {
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

	if err := c.checkKeptExtras(current, add); err != nil {
		return nil, g.fail(c, err)
	}

	target := slices.DeleteFunc(slices.Clone(current), func(rec dnsprovider.Record) bool { return slices.Contains(remove, rec.Value) })

	// A value added that the RRset holds keeps its record, its Record
	// Extras merged with those sent.
	for _, v := range add {
		if i := indexOfValue(target, v); i >= 0 {
			target[i].Extras = v.GetExtras()
		}
	}

	added := slices.DeleteFunc(slices.Clone(add), func(v *dnsgatev1.RecordValue) bool { return indexOfValue(current, v) >= 0 })
	if len(added) > 0 {
		if ttl == 0 {
			ttl = rrsetTTL(current)
		}

		if ttl == 0 {
			return nil, g.fail(c, invalidRecord("no TTL: give one to create the RRset"))
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
		return nil, g.fail(c, notFound("no such RRset"))
	}

	if _, err := g.apply(c, zone, current, nil); err != nil {
		return nil, err
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_DeleteRecord{
		DeleteRecord: &dnsgatev1.DeleteRecordResponse{},
	}}, nil
}

// valuesOf returns the values of records.
func valuesOf(records []*dnsgatev1.RecordValue) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.GetValue())
	}

	return out
}

// indexOfValue returns the index of the record of records that holds the
// value of v, or -1 for none.
func indexOfValue(records []dnsprovider.Record, v *dnsgatev1.RecordValue) int {
	return slices.IndexFunc(records, func(rec dnsprovider.Record) bool { return rec.Value == v.GetValue() })
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
func (c *dnsCall) checkRecords(ttl uint32, values []*dnsgatev1.RecordValue) ([]dnsprovider.Record, error) {
	if len(values) == 0 {
		return nil, invalidRequest("no values: an RRset holds at least one")
	}

	if err := c.checkValues(valuesOf(values)); err != nil {
		return nil, err
	}

	if err := c.checkExtras(values); err != nil {
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

// checkExtras checks that each Record Extra sent with values is one the
// call's Provider type reads on records of the call's type, and set in the
// form it takes (dnsprovider.Factory.CheckExtras), or else "", which
// clears it.
func (c *dnsCall) checkExtras(values []*dnsgatev1.RecordValue) error {
	for _, v := range values {
		for k, x := range v.GetExtras() {
			if s, ok := c.factory.Extra(k); x == "" && (!ok || !s.AppliesTo(c.perm.Type)) {
				return invalidRecord("a Record Extra is not one the Provider reads on records of this type")
			}
		}

		if err := c.factory.CheckExtras(dnsprovider.Record{Type: c.perm.Type, Extras: setExtras(v.GetExtras())}); err != nil {
			return invalidRecord("a Record Extra is not one the Provider reads on records of this type, or not in the form it takes")
		}
	}

	return nil
}

// checkKeptExtras checks that values change no Record Extra the call's
// Provider type keeps on write: one sent for a value of a record of
// current must be the record's own, "" where it has none, and none may be
// sent for a new value, which no record holds, not even as "".
func (c *dnsCall) checkKeptExtras(current []dnsprovider.Record, values []*dnsgatev1.RecordValue) error {
	for _, v := range values {
		i := indexOfValue(current, v)

		for k, x := range v.GetExtras() {
			if c.writable(k) {
				continue
			}

			if i < 0 {
				return invalidRecord("a Record Extra the Provider keeps on write is given for a new value")
			}

			if x != current[i].Extras[k] {
				return invalidRecord("a Record Extra the Provider keeps on write is given another value than the record's")
			}
		}
	}

	return nil
}

// checkTTL checks that ttl is in the range the call's Provider type
// takes.
func (c *dnsCall) checkTTL(ttl uint32) error {
	if err := c.factory.TTLRange().Check(ttl); err != nil {
		return invalidRecord(err.Error())
	}

	return nil
}

// records returns the records of the call's RRset with ttl and values,
// each with the Record Extras sent with its value, as plan takes them.
func (c *dnsCall) records(ttl uint32, values []*dnsgatev1.RecordValue) []dnsprovider.Record {
	name := dnsname.Absolute(c.perm.Zone, c.perm.Name)

	out := make([]dnsprovider.Record, 0, len(values))
	for _, v := range values {
		out = append(out, dnsprovider.Record{Type: c.perm.Type, Name: name, Value: v.GetValue(), TTL: ttl, Extras: maps.Clone(v.GetExtras())})
	}

	return out
}

// writable reports whether the call's Provider type writes the Record
// Extra key as given.
func (c *dnsCall) writable(key string) bool {
	s, ok := c.factory.Extra(key)

	return ok && s.Writable
}

// named reports whether the call's Provider type declares the Record
// Extra key by name, not only as one of the other fields of its API
// (dnsprovider.ExtraOther).
func (c *dnsCall) named(key string) bool {
	s, ok := c.factory.Extra(key)

	return ok && key != dnsprovider.ExtraOther && s.Key == key
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
	changes, kept := plan(current, target, c.writable)

	after := kept

	applied := 0
	c.event.ChangesApplied = &applied

	if len(changes) > 0 {
		c.event.Changes = auditChanges(changes, c.named)

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

// auditChanges returns changes as the audit event of the call shows them:
// each record's value, TTL and the Record Extras named reports the
// Provider type declares by name. Those it reads only as other fields of
// its API (dnsprovider.ExtraOther) stay out of the audit log.
func auditChanges(changes []dnsprovider.Change, named func(key string) bool) []audit.Change {
	record := func(r dnsprovider.Record) *audit.Record {
		extras := maps.Clone(r.Extras)
		maps.DeleteFunc(extras, func(k, _ string) bool { return !named(k) })

		if len(extras) == 0 {
			extras = nil
		}

		return &audit.Record{Value: r.Value, TTL: r.TTL, Extras: extras}
	}

	out := make([]audit.Change, 0, len(changes))
	for _, ch := range changes {
		switch ch.Kind {
		case dnsprovider.ChangeAdd:
			out = append(out, audit.Change{Kind: audit.ChangeAdd, After: record(ch.After)})
		case dnsprovider.ChangeModify:
			out = append(out, audit.Change{Kind: audit.ChangeModify, Before: record(ch.Before), After: record(ch.After)})
		case dnsprovider.ChangeDelete:
			out = append(out, audit.Change{Kind: audit.ChangeDelete, Before: record(ch.Before)})
		}
	}

	return out
}

// plan returns the changes that turn the records current of an RRset into
// target, and the records of current it leaves as they are. A record of
// current is kept for the target record of its value, its TTL and Record
// Extras modified if they differ; each other one is modified into a
// target record no record holds the value of, while there are some, and
// deleted after. The target records left are added. Modifying rather
// than deleting and adding keeps the RRset from going empty while it is
// replaced.
//
// A target record's Extras are the keys sent for its value, merged into
// the record's own as mergeExtras does. A new value starts with the
// Record Extras it was sent, plus, where it reuses a record, the ones
// writable reports a write does not set, as the Provider keeps them; the
// reused record's others are cleared.
func plan(current, target []dnsprovider.Record, writable func(key string) bool) (changes []dnsprovider.Change, kept []dnsprovider.Record) {
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

		after := current[i]
		after.TTL, after.Extras = t.TTL, mergeExtras(current[i].Extras, t.Extras)

		if current[i].TTL == t.TTL && dnsprovider.SameExtras(setExtras(current[i].Extras), setExtras(after.Extras)) {
			kept = append(kept, current[i])

			continue
		}

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
		after.Extras = mergeExtras(clearedExtras(rec.Extras, writable), unmatched[0].Extras)
		unmatched = unmatched[1:]
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: rec, After: after})
	}

	for _, t := range unmatched {
		t.Extras = mergeExtras(nil, t.Extras)
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: t})
	}

	return changes, kept
}

// mergeExtras returns the Record Extras held with those sent merged in,
// per key: a key sent sets its Record Extra, a key sent as "" clears it
// and a key not sent keeps its value. A Record Extra cleared stays as ""
// for the Provider to clear; one held by no record is left out. nil for
// none.
func mergeExtras(held, sent map[string]string) map[string]string {
	out := maps.Clone(held)

	for k, v := range sent {
		if _, ok := held[k]; v == "" && !ok {
			continue
		}

		if out == nil {
			out = map[string]string{}
		}

		out[k] = v
	}

	return out
}

// clearedExtras returns the Record Extras held with each one writable
// reports a write sets cleared, as "".
func clearedExtras(held map[string]string, writable func(key string) bool) map[string]string {
	out := maps.Clone(held)

	for k := range out {
		if writable(k) {
			out[k] = ""
		}
	}

	return out
}

// setExtras returns the Record Extras of extras that are set, without
// those of "", which a write clears.
func setExtras(extras map[string]string) map[string]string {
	out := maps.Clone(extras)
	maps.DeleteFunc(out, func(_, v string) bool { return v == "" })

	return out
}
