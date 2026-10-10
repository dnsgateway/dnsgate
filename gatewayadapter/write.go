package gatewayadapter

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/dnsname"
)

// errNotMade is the error of a change not made because a write of the
// Changeset failed before it.
var errNotMade = errors.New("gateway adapter: not made, as another change of the Changeset failed")

// CreateRecord adds a Record, as a one-change Changeset.
func (a *adapter) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return a.one(ctx, zone, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: r})
}

// UpdateRecord changes before into after, as a one-change Changeset.
func (a *adapter) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return a.one(ctx, zone, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after})
}

// DeleteRecord removes a Record, as a one-change Changeset.
func (a *adapter) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) error {
	_, err := a.one(ctx, zone, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: r})

	return err
}

// one applies a one-change Changeset and returns its Record, or the
// Changeset's error or the change's own.
func (a *adapter) one(ctx context.Context, zone dnsprovider.Zone, c dnsprovider.Change) (dnsprovider.Record, error) {
	res, err := a.ApplyChangeset(ctx, dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{c}})
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if r := res.Results[0]; r.Err != nil {
		return dnsprovider.Record{}, r.Err
	}

	return res.Results[0].Record, nil
}

// rrset is one RRset a Changeset touches: as the Gateway holds it, and as
// the Changeset leaves it.
type rrset struct {
	// name is relative to the zone, typ in upper case.
	name, typ string
	// current are the RRset's records as read, none for an RRset the
	// zone does not hold, and ttl its TTL as read.
	current []dnsprovider.Record
	ttl     uint32
	// target are the records the RRset is to hold.
	target []target
	// err is why the RRset was not written; written marks an RRset the
	// Gateway wrote, and stored are its records after.
	err     error
	written bool
	stored  []dnsprovider.Record
}

// target is a record an RRset is to hold.
type target struct {
	dnsprovider.Record
	// set marks the After of a change, whose Record Extras are sent; a
	// record of current no change touches is sent bare, and the Gateway
	// keeps its Record Extras.
	set bool
}

// held returns the record of current holding value, or nil.
func (s *rrset) held(value string) *dnsprovider.Record {
	if i := slices.IndexFunc(s.current, func(r dnsprovider.Record) bool { return r.Value == value }); i >= 0 {
		return &s.current[i]
	}

	return nil
}

// index returns the index of the target record holding value, or -1.
func (s *rrset) index(value string) int {
	return slices.IndexFunc(s.target, func(t target) bool { return t.Value == value })
}

// ApplyChangeset writes each RRset the Changeset touches whole: it reads
// each one, works out the records it is to hold, and writes it with
// create, update or delete, naming the RRset as read as the Expected RRset
// on each update and delete, so a write built on an RRset that changed
// since is refused with dnsprovider.ErrConflict. It never patches.
//
// The RRsets the Changeset empties are written first, then those it
// changes, then those it creates. The writes stop at the first that
// fails: there is no atomicity across RRsets. Each change then fails with
// the error of the RRset that failed, or errNotMade when its own were not
// written; one whose RRsets were all written succeeds. A change built
// from a Record the RRset no longer holds fails with
// dnsprovider.ErrNotFound, one that would add a Record the RRset holds
// with dnsprovider.ErrConflict: then nothing is written. A failed read is
// the Changeset's error.
//
// Every record of an RRset takes one TTL: the lowest of the TTLs the
// changes give it, or the RRset's own when they give none.
func (a *adapter) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i].Change = c
	}

	// touched are the RRsets each change touches: its Before's, then its
	// After's.
	touched := make([][]*rrset, len(cs.Changes))
	sets := map[string]*rrset{}

	var (
		order  []*rrset
		failed bool
	)

	rrsetOf := func(r dnsprovider.Record) (*rrset, error) {
		name, typ, err := rrsetKey(cs.Zone.Name, r)
		if err != nil {
			return nil, err
		}

		key := name + "\x00" + typ
		if s, ok := sets[key]; ok {
			return s, nil
		}

		s := &rrset{name: name, typ: typ}
		sets[key] = s
		order = append(order, s)

		return s, nil
	}

	for i, c := range cs.Changes {
		var err error

		touched[i], err = touchedBy(c, rrsetOf)
		if err != nil {
			res.Results[i].Err = err
			failed = true
		}
	}

	if failed {
		return notMade(res), nil
	}

	for _, s := range order {
		if err := a.read(ctx, cs.Zone.Name, s); err != nil {
			return dnsprovider.ApplyResult{}, err
		}
	}

	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		if err := plan(cs.Changes[i], touched[i]); err != nil {
			res.Results[i].Err = err
			failed = true
		}
	}

	if failed {
		return notMade(res), nil
	}

	f := a.providerType(ctx)

	for _, s := range writeOrder(order) {
		if failed {
			s.err = errNotMade

			continue
		}

		if s.err = a.write(ctx, cs.Zone.Name, s, f); s.err != nil {
			failed = true
		}
	}

	for i, c := range cs.Changes {
		res.Results[i] = result(cs.Zone.Name, c, touched[i])
	}

	return res, nil
}

// notMade fails each change of res not failed yet with errNotMade.
func notMade(res dnsprovider.ApplyResult) dnsprovider.ApplyResult {
	for i := range res.Results {
		if res.Results[i].Err == nil {
			res.Results[i].Err = errNotMade
		}
	}

	return res
}

// touchedBy returns the RRsets a change touches, through rrsetOf: its
// Before's, for a modification or deletion, then its After's, for an
// addition or modification.
func touchedBy(c dnsprovider.Change, rrsetOf func(dnsprovider.Record) (*rrset, error)) ([]*rrset, error) {
	var recs []dnsprovider.Record

	switch c.Kind {
	case dnsprovider.ChangeAdd:
		recs = []dnsprovider.Record{c.After}
	case dnsprovider.ChangeModify:
		recs = []dnsprovider.Record{c.Before, c.After}
	case dnsprovider.ChangeDelete:
		recs = []dnsprovider.Record{c.Before}
	default:
		return nil, fmt.Errorf("gateway adapter: unknown change kind %d", c.Kind)
	}

	out := make([]*rrset, 0, len(recs))

	for _, r := range recs {
		s, err := rrsetOf(r)
		if err != nil {
			return nil, err
		}

		out = append(out, s)
	}

	return out, nil
}

// rrsetKey returns the name, relative to zone, and the type in upper case
// of the RRset of r.
func rrsetKey(zone string, r dnsprovider.Record) (name, typ string, err error) {
	abs, err := dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return "", "", fmt.Errorf("gateway adapter: %w", err)
	}

	name, ok := dnsname.Relative(dnsname.Zone(zone), abs)
	if !ok {
		return "", "", fmt.Errorf("gateway adapter: %s is not inside the zone %s", r.Name, zone)
	}

	if r.Type == "" {
		return "", "", errors.New("gateway adapter: a Record has no type")
	}

	return name, strings.ToUpper(r.Type), nil
}

// read reads the RRset s as the Gateway holds it, none when it holds
// none, and starts its target as it is.
func (a *adapter) read(ctx context.Context, zone string, s *rrset) error {
	resp, err := a.client.GetRecord(ctx, &dnsgatev1.GetRecordRequest{Token: a.token, Egress: a.egress, Zone: zone, Name: s.name, Type: s.typ})

	switch err = providerError(err); {
	case errors.Is(err, dnsprovider.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("gateway adapter: reading the RRset %s %s: %w", s.name, s.typ, err)
	}

	s.current = recordsOf(zone, resp.GetRecordSet())
	s.ttl = resp.GetRecordSet().GetTtl()

	for _, r := range s.current {
		s.target = append(s.target, target{Record: r})
	}

	return nil
}

// plan makes the change c to the targets of the RRsets it touches: it
// removes its Before from the first, and adds its After to the last.
func plan(c dnsprovider.Change, touched []*rrset) error {
	source, at := (*rrset)(nil), -1
	if c.Kind != dnsprovider.ChangeAdd {
		source = touched[0]
		if at = source.index(c.Before.Value); at < 0 {
			return fmt.Errorf("gateway adapter: the RRset %s %s no longer holds %q: %w", source.name, source.typ, c.Before.Value, dnsprovider.ErrNotFound)
		}
	}

	if c.Kind != dnsprovider.ChangeDelete {
		dest := touched[len(touched)-1]
		if i := dest.index(c.After.Value); i >= 0 && (dest != source || i != at) {
			return fmt.Errorf("gateway adapter: the RRset %s %s holds %q already: %w", dest.name, dest.typ, c.After.Value, dnsprovider.ErrConflict)
		}

		if source != nil {
			source.target = slices.Delete(source.target, at, at+1)
		}

		dest.target = append(dest.target, target{Record: c.After, set: true})

		return nil
	}

	source.target = slices.Delete(source.target, at, at+1)

	return nil
}

// writeOrder returns the RRsets of order to write, in the order they are
// written: those the Changeset empties, then those it changes, then
// those it creates, each in order.
func writeOrder(order []*rrset) []*rrset {
	var emptied, changed, created []*rrset

	for _, s := range order {
		switch {
		case len(s.current) > 0 && len(s.target) == 0:
			emptied = append(emptied, s)
		case len(s.current) > 0:
			changed = append(changed, s)
		case len(s.target) > 0:
			created = append(created, s)
		}
	}

	return slices.Concat(emptied, changed, created)
}

// write writes the RRset s as its target: delete when it is to hold no
// record, create when it holds none yet, else update, unless the target
// is the RRset as it is. f is the token's Provider type.
func (a *adapter) write(ctx context.Context, zone string, s *rrset, f dnsprovider.Factory) error {
	ttl := s.targetTTL()

	var err error

	switch {
	case len(s.target) == 0:
		_, err = a.client.DeleteRecord(ctx, &dnsgatev1.DeleteRecordRequest{
			Token: a.token, Egress: a.egress, Zone: zone, Name: s.name, Type: s.typ, Expect: s.expected(),
		})
	case len(s.current) == 0:
		var resp *dnsgatev1.CreateRecordResponse

		resp, err = a.client.CreateRecord(ctx, &dnsgatev1.CreateRecordRequest{
			Token: a.token, Egress: a.egress, Zone: zone, Name: s.name, Type: s.typ, Ttl: ttl, Records: s.values(f),
		})
		s.stored = recordsOf(zone, resp.GetRecordSet())
	case s.unchanged(ttl, f):
		s.stored = s.current

		return nil
	default:
		var resp *dnsgatev1.UpdateRecordResponse

		resp, err = a.client.UpdateRecord(ctx, &dnsgatev1.UpdateRecordRequest{
			Token: a.token, Egress: a.egress, Zone: zone, Name: s.name, Type: s.typ, Ttl: ttl, Records: s.values(f), Expect: s.expected(),
		})
		s.stored = recordsOf(zone, resp.GetRecordSet())
	}

	if err != nil {
		return fmt.Errorf("gateway adapter: writing the RRset %s %s: %w", s.name, s.typ, providerError(err))
	}

	s.written = true

	return nil
}

// targetTTL is the TTL the RRset is written with: the lowest a change
// gives it, else its own.
func (s *rrset) targetTTL() uint32 {
	ttl := uint32(0)

	for _, t := range s.target {
		if t.set && (ttl == 0 || t.TTL < ttl) {
			ttl = t.TTL
		}
	}

	if ttl == 0 {
		return s.ttl
	}

	return ttl
}

// unchanged reports whether the target, with ttl, is the RRset as it is:
// the same values and TTL, and Record Extras a write would leave as they
// are. f is the token's Provider type.
func (s *rrset) unchanged(ttl uint32, f dnsprovider.Factory) bool {
	if ttl != s.ttl || len(s.target) != len(s.current) {
		return false
	}

	for _, t := range s.target {
		held := s.held(t.Value)
		if held == nil {
			return false
		}

		if t.set && !dnsprovider.SameExtras(held.Extras, applied(held.Extras, sentExtras(held, t.Extras, f))) {
			return false
		}
	}

	return true
}

// applied returns the Record Extras held after a write sends sent: each
// sent "" clears its key.
func applied(held, sent map[string]string) map[string]string {
	out := maps.Clone(held)
	if out == nil {
		out = map[string]string{}
	}

	for k, v := range sent {
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
	}

	return out
}

// expected is the Expected RRset of a write of s: the RRset as read.
func (s *rrset) expected() *dnsgatev1.ExpectedRRset {
	out := &dnsgatev1.ExpectedRRset{Ttl: s.ttl}
	for _, r := range s.current {
		out.Records = append(out.Records, &dnsgatev1.RecordValue{Value: r.Value, Extras: maps.Clone(r.Extras)})
	}

	return out
}

// values are the values a write of s sends, each with the Record Extras
// it changes. A value no change touches is sent bare, and the Gateway
// keeps its Record Extras as they are. A value a change gives is sent
// with its Record Extras, and with "" for each one the record it keeps
// has and the change does not give, which clears it, unless the Provider
// type f keeps that one on write: the Gateway refuses to clear it. A
// value the RRset does not hold yet is sent without the Record Extras f
// keeps on write, which the Gateway refuses on a new value.
func (s *rrset) values(f dnsprovider.Factory) []*dnsgatev1.RecordValue {
	out := make([]*dnsgatev1.RecordValue, 0, len(s.target))

	for _, t := range s.target {
		v := &dnsgatev1.RecordValue{Value: t.Value}
		if t.set {
			v.Extras = sentExtras(s.held(t.Value), t.Extras, f)
		}

		out = append(out, v)
	}

	return out
}

// sentExtras returns the Record Extras sent for want, the Record Extras
// a value is to have, given the record that holds the value, nil for
// none.
func sentExtras(held *dnsprovider.Record, want map[string]string, f dnsprovider.Factory) map[string]string {
	out := map[string]string{}

	for k, v := range want {
		if v == "" {
			continue
		}

		if s, ok := f.Extra(k); held == nil && ok && !s.Writable {
			continue
		}

		out[k] = v
	}

	if held != nil {
		for k, v := range held.Extras {
			if v == "" || want[k] != "" {
				continue
			}

			if s, ok := f.Extra(k); ok && !s.Writable {
				continue
			}

			out[k] = ""
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

// result is the result of the change c, which touched the RRsets
// touched: the error of the first that was not written, or its After as
// the Gateway stored it.
func result(zone string, c dnsprovider.Change, touched []*rrset) dnsprovider.ChangeResult {
	for _, s := range touched {
		if s.err == nil {
			continue
		}

		err := s.err

		for _, w := range touched {
			if w.written {
				err = fmt.Errorf("%w; the RRset %s %s is written already", err, w.name, w.typ)
			}
		}

		return dnsprovider.ChangeResult{Change: c, Err: err}
	}

	if c.Kind == dnsprovider.ChangeDelete {
		return dnsprovider.ChangeResult{Change: c}
	}

	dest := touched[len(touched)-1]
	if i := slices.IndexFunc(dest.stored, func(r dnsprovider.Record) bool { return r.Value == c.After.Value }); i >= 0 {
		return dnsprovider.ChangeResult{Change: c, Record: dest.stored[i]}
	}

	rec := c.After
	if abs, err := dnsprovider.QualifyName(zone, rec.Name); err == nil {
		rec.Name = abs
	}

	rec.ID = contentID(rec)

	return dnsprovider.ChangeResult{Change: c, Record: rec}
}
