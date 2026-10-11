package gateway

import (
	"cmp"
	"slices"
	"strings"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"

	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// listRecords lists the RRsets of a zone the token covers. The token needs
// list on records in the zone; each RRset is then filtered by the names
// and types filters of the rules that allow list there. The list is a
// Partial View unless the token covers every name and type in the zone.
func (g *Gateway) listRecords(r *request, req *dnsgatev1.ListRecordsRequest) (*dnsgatev1.Response, error) {
	c, err := g.startDNSCall(r, audit.EventRecordsList, req,
		permission.Request{Verb: permission.VerbList, Resource: permission.ResourceRecords, Zone: req.GetZone()}, checkZoneOf)
	if err != nil {
		return nil, err
	}

	_, records, err := g.readRecords(c, dnsprovider.RecordFilter{})
	if err != nil {
		return nil, err
	}

	pr := c.perm
	sets := recordSets(pr.Zone, records, func(name, typ string) bool {
		pr.Name, pr.Type = name, typ

		return permission.Allows(c.claims.Permissions, pr)
	})

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ListRecords{
		ListRecords: &dnsgatev1.ListRecordsResponse{RecordSets: sets, Partial: c.partialView()},
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

	_, records, err := g.readRRset(c)
	if err != nil {
		return nil, err
	}

	sets := recordSets(c.perm.Zone, records, keepAll)
	if len(sets) == 0 {
		return nil, notFound("no such RRset")
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_GetRecord{
		GetRecord: &dnsgatev1.GetRecordResponse{RecordSet: sets[0]},
	}}, nil
}

// readRecords reads the call's zone and its records that match f from its
// Provider.
func (g *Gateway) readRecords(c *dnsCall, f dnsprovider.RecordFilter) (dnsprovider.Zone, []dnsprovider.Record, error) {
	z, err := c.provider.GetZone(c.ctx, c.perm.Zone)
	if err != nil {
		return dnsprovider.Zone{}, nil, g.providerFailed(c, err)
	}

	set, err := c.provider.ListRecords(c.ctx, z, f)
	if err != nil {
		return dnsprovider.Zone{}, nil, g.providerFailed(c, err)
	}

	return z, set.Records, nil
}

// recordSets groups the records of zone into RRsets, keeping those keep
// returns true for, sorted by name and type. Names are relative to zone
// and types in upper case; each RRset has the lowest TTL of its records,
// and each value its record's Record Extras, but those of "", which a
// write cleared.
func recordSets(zone string, records []dnsprovider.Record, keep func(name, typ string) bool) []*dnsgatev1.RecordSet {
	type key struct{ name, typ string }

	byKey := map[key]*dnsgatev1.RecordSet{}

	var sets []*dnsgatev1.RecordSet

	for _, rec := range records {
		name, ok := dnsname.Relative(zone, rec.Name)
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
		s.Records = append(s.Records, &dnsgatev1.RecordValue{Value: rec.Value, Extras: setExtras(rec.Extras)})
	}

	slices.SortFunc(sets, func(a, b *dnsgatev1.RecordSet) int {
		return cmp.Or(strings.Compare(a.GetName(), b.GetName()), strings.Compare(a.GetType(), b.GetType()))
	})

	return sets
}

// keepAll is the recordSets filter that keeps every RRset.
func keepAll(string, string) bool { return true }
