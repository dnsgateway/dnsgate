package gateway

import (
	"cmp"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// listRecords lists the RRsets of a zone the token covers. The token needs
// list on records in the zone; each RRset is then filtered by the names
// and types filters of the rules that allow list there.
func (g *Gateway) listRecords(r *request, req *dnsgatev1.ListRecordsRequest) (*dnsgatev1.Response, error) {
	c, err := g.startDNSCall(r, audit.EventRecordsList, req,
		permission.Request{Verb: permission.VerbList, Resource: permission.ResourceRecords, Zone: req.GetZone()}, checkZoneOf)
	if err != nil {
		return nil, err
	}

	records, err := g.readRecords(c, dnsprovider.RecordFilter{})
	if err != nil {
		return nil, err
	}

	pr := c.perm
	sets := recordSets(pr.Zone, records, func(name, typ string) bool {
		pr.Name, pr.Type = name, typ

		return permission.Allows(c.claims.Permissions, pr)
	})

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ListRecords{
		ListRecords: &dnsgatev1.ListRecordsResponse{RecordSets: sets},
	}}, nil
}

// getRecord reads one RRset. The token needs get on records for its zone,
// name and type.
func (g *Gateway) getRecord(r *request, req *dnsgatev1.GetRecordRequest) (*dnsgatev1.Response, error) {
	c, err := g.startDNSCall(r, audit.EventRecordsGet, req, permission.Request{
		Verb: permission.VerbGet, Resource: permission.ResourceRecords, Zone: req.GetZone(), Name: req.GetName(), Type: req.GetType(),
	}, checkRecordOf)
	if err != nil {
		return nil, err
	}

	zone, name, typ := c.perm.Zone, c.perm.Name, c.perm.Type

	// Contains narrows the Provider's answer to names ending in this one;
	// the exact name is matched below.
	records, err := g.readRecords(c, dnsprovider.RecordFilter{Type: typ, Contains: absoluteName(zone, name) + "."})
	if err != nil {
		return nil, err
	}

	sets := recordSets(zone, records, func(n, t string) bool { return n == name && t == typ })
	if len(sets) == 0 {
		return nil, notFound("no such record set")
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_GetRecord{
		GetRecord: &dnsgatev1.GetRecordResponse{RecordSet: sets[0]},
	}}, nil
}

// readRecords reads the records of the call's zone that match f from its
// Provider.
func (g *Gateway) readRecords(c *dnsCall, f dnsprovider.RecordFilter) ([]dnsprovider.Record, error) {
	z, err := c.provider.Zone(c.ctx, c.perm.Zone)
	if err != nil {
		return nil, g.providerFailed(c, err)
	}

	set, err := c.provider.Records(c.ctx, z, f)
	if err != nil {
		return nil, g.providerFailed(c, err)
	}

	return set.Records, nil
}

// recordSets groups the records of zone into RRsets, keeping those keep
// returns true for, sorted by name and type. Names are relative to zone
// and types in upper case; each RRset has the lowest TTL of its records.
func recordSets(zone string, records []dnsprovider.Record, keep func(name, typ string) bool) []*dnsgatev1.RecordSet {
	type key struct{ name, typ string }

	byKey := map[key]*dnsgatev1.RecordSet{}

	var sets []*dnsgatev1.RecordSet

	for _, rec := range records {
		name, ok := relativeName(zone, rec.Name)
		if !ok {
			continue
		}

		k := key{name, strings.ToUpper(rec.Type)}
		if !keep(k.name, k.typ) {
			continue
		}

		s, ok := byKey[k]
		if !ok {
			s = &dnsgatev1.RecordSet{Name: k.name, Type: k.typ, Ttl: rec.TTL}
			byKey[k] = s
			sets = append(sets, s)
		}

		s.Ttl = min(s.GetTtl(), rec.TTL)
		s.Values = append(s.Values, rec.Value)
	}

	slices.SortFunc(sets, func(a, b *dnsgatev1.RecordSet) int {
		return cmp.Or(strings.Compare(a.GetName(), b.GetName()), strings.Compare(a.GetType(), b.GetType()))
	})

	return sets
}
