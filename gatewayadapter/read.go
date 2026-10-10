package gatewayadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// Account inspects the Service Token, and lists the zones too when its
// Permissions grant list on zones, which proves the Provider Credential
// still works. The Tenant is the token: its ID (jti) and its Service
// Account (sub). A token the Gateway does not accept, such as a Bound
// Token, for which the Gateway Adapter sends no Identity Token, is
// dnsprovider.ErrUnauthorized.
func (a *adapter) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	inspected, err := a.client.InspectToken(ctx, a.token)
	if err != nil {
		err = providerError(ctx, err)
		if errors.Is(err, dnsprovider.ErrUnauthorized) {
			err = fmt.Errorf("the Gateway did not accept the Service Token, and a Bound Token is not usable through the Gateway Adapter: %w", err)
		}

		return dnsprovider.AccountInfo{}, err
	}

	a.learnProvider(inspected.GetProvider())

	if a.mayListZones(inspected.GetPermissions()) {
		if _, err := a.client.ListZones(ctx, &dnsgatev1.ListZonesRequest{Token: a.token, Egress: a.egress}); err != nil {
			return dnsprovider.AccountInfo{}, providerError(ctx, err)
		}
	}

	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: inspected.GetJti(), Name: inspected.GetSub()}}, nil
}

// mayListZones reports whether perms grant list on zones through the
// Gateway Adapter's Egress.
func (a *adapter) mayListZones(perms []*dnsgatev1.Permission) bool {
	egress, _ := permission.EgressFromAPI(a.egress)

	return permission.Allows(permission.FromAPI(perms), permission.Request{Verb: permission.VerbList, Resource: permission.ResourceZones, Egress: egress})
}

// states maps each zone state of the API to its Hosting State.
var states = map[dnsgatev1.Zone_State]dnsprovider.HostingState{
	dnsgatev1.Zone_STATE_ACTIVE:  dnsprovider.HostingActive,
	dnsgatev1.Zone_STATE_PENDING: dnsprovider.HostingPending,
	dnsgatev1.Zone_STATE_MOVED:   dnsprovider.HostingMoved,
}

// zoneOf returns the Zone of z, its name as its ID: the Gateway names
// zones by name alone.
func zoneOf(z *dnsgatev1.Zone) dnsprovider.Zone {
	var ns []string
	if len(z.GetNameservers()) > 0 {
		ns = slices.Clone(z.GetNameservers())
	}

	return dnsprovider.Zone{ID: z.GetName(), Name: z.GetName(), State: states[z.GetState()], Nameservers: ns}
}

// Zones lists the zones the token covers that match f. The token needs
// list on zones.
func (a *adapter) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	resp, err := a.client.ListZones(ctx, &dnsgatev1.ListZonesRequest{Token: a.token, Egress: a.egress})
	if err != nil {
		return nil, providerError(ctx, err)
	}

	var out []dnsprovider.Zone

	for _, z := range resp.GetZones() {
		if zone := zoneOf(z); dnsprovider.MatchZone(f, zone) {
			out = append(out, zone)
		}
	}

	return out, nil
}

// Zone reads one zone by its name. The token needs get on zones for it.
func (a *adapter) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	resp, err := a.client.GetZone(ctx, &dnsgatev1.GetZoneRequest{Token: a.token, Egress: a.egress, Zone: name})
	if err != nil {
		return dnsprovider.Zone{}, providerError(ctx, err)
	}

	return zoneOf(resp.GetZone()), nil
}

// Records lists the records of the zone's RRsets the token covers that
// match f, one Record per value, without the SOA serial, which the
// Gateway does not report. The token needs list on records in the zone.
func (a *adapter) Records(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	resp, err := a.client.ListRecords(ctx, &dnsgatev1.ListRecordsRequest{Token: a.token, Egress: a.egress, Zone: zone.Name})
	if err != nil {
		return dnsprovider.RecordSet{}, providerError(ctx, err)
	}

	var out dnsprovider.RecordSet

	for _, set := range resp.GetRecordSets() {
		for _, r := range recordsOf(zone.Name, set) {
			if dnsprovider.MatchRecord(f, r) {
				out.Records = append(out.Records, r)
			}
		}
	}

	return out, nil
}

// recordsOf returns the Records of an RRset of zone: one per value, each
// with the RRset's TTL, its own Record Extras and an ID built from its
// content.
func recordsOf(zone string, set *dnsgatev1.RecordSet) []dnsprovider.Record {
	name := dnsname.Absolute(dnsname.Zone(zone), set.GetName())

	out := make([]dnsprovider.Record, 0, len(set.GetRecords()))
	for _, v := range set.GetRecords() {
		r := dnsprovider.Record{Type: set.GetType(), Name: name, Value: v.GetValue(), TTL: set.GetTtl()}
		if len(v.GetExtras()) > 0 {
			r.Extras = maps.Clone(v.GetExtras())
		}

		r.ID = contentID(r)
		out = append(out, r)
	}

	return out
}

// contentID is the ID of a Record, built from its type, name and value:
// the Gateway has no record IDs.
func contentID(r dnsprovider.Record) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(r.Type) + "\x00" + dnsname.Zone(r.Name) + "\x00" + r.Value))

	return hex.EncodeToString(sum[:])
}
