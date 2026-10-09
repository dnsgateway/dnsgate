package gateway

import (
	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// listZones lists the zones the Provider Credential reaches and the token
// covers. The token needs list on zones; each zone is then filtered by the
// token's zones filter.
func (g *Gateway) listZones(r *request, req *dnsgatev1.ListZonesRequest) (*dnsgatev1.Response, error) {
	c := newDNSCall(r, audit.EventZonesList, permission.VerbList)

	claims, err := g.openToken(c, req.GetToken())
	if err != nil {
		return nil, err
	}

	pr := permission.Request{Verb: permission.VerbList, Resource: permission.ResourceZones}

	egress, err := g.authorize(c, claims, req.GetEgress(), pr)
	if err != nil {
		return nil, err
	}

	p, err := g.connect(c, claims)
	if err != nil {
		return nil, err
	}

	zones, err := p.Zones(r.ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		return nil, g.providerFailed(c, err)
	}

	out := &dnsgatev1.ListZonesResponse{}

	pr.Egress = egress

	for _, z := range zones {
		pr.Zone = z.Name
		if permission.Allows(claims.Permissions, pr) {
			out.Zones = append(out.Zones, zoneToAPI(z))
		}
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ListZones{ListZones: out}}, nil
}

// getZone reads one zone. The token needs get on zones for it.
func (g *Gateway) getZone(r *request, req *dnsgatev1.GetZoneRequest) (*dnsgatev1.Response, error) {
	c := newDNSCall(r, audit.EventZonesGet, permission.VerbGet)

	claims, err := g.openToken(c, req.GetToken())
	if err != nil {
		return nil, err
	}

	zone, err := checkZone(req.GetZone())
	if err != nil {
		return nil, g.refuse(c, audit.ResultDenied, err)
	}

	c.event.Zone = zone

	pr := permission.Request{Verb: permission.VerbGet, Resource: permission.ResourceZones, Zone: zone}
	if _, err := g.authorize(c, claims, req.GetEgress(), pr); err != nil {
		return nil, err
	}

	p, err := g.connect(c, claims)
	if err != nil {
		return nil, err
	}

	z, err := p.Zone(r.ctx, zone)
	if err != nil {
		return nil, g.providerFailed(c, err)
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_GetZone{
		GetZone: &dnsgatev1.GetZoneResponse{Zone: zoneToAPI(z)},
	}}, nil
}

var zoneStates = map[dnsprovider.HostingState]dnsgatev1.Zone_State{
	dnsprovider.HostingActive:  dnsgatev1.Zone_STATE_ACTIVE,
	dnsprovider.HostingPending: dnsgatev1.Zone_STATE_PENDING,
	dnsprovider.HostingMoved:   dnsgatev1.Zone_STATE_MOVED,
}

func zoneToAPI(z dnsprovider.Zone) *dnsgatev1.Zone {
	return &dnsgatev1.Zone{
		Name:        permission.ZoneName(z.Name),
		State:       zoneStates[z.State],
		Nameservers: z.Nameservers,
	}
}
