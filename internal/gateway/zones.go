package gateway

import (
	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"

	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/dnsname"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// listZones lists the zones the Provider Credential reaches and the token
// covers. The token needs list on zones; each zone is then filtered by the
// token's zones filter.
func (g *Gateway) listZones(r *request, req *dnsgatev1.ListZonesRequest) (*dnsgatev1.Response, error) {
	c, err := g.startDNSCall(r, audit.EventZonesList, req,
		permission.Request{Verb: permission.VerbList, Resource: permission.ResourceZones}, nil)
	if err != nil {
		return nil, err
	}

	zones, err := c.provider.Zones(c.ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		return nil, g.providerFailed(c, err)
	}

	out := &dnsgatev1.ListZonesResponse{}

	pr := c.perm
	for _, z := range zones {
		pr.Zone = z.Name
		if permission.Allows(c.claims.Permissions, pr) {
			out.Zones = append(out.Zones, zoneToAPI(z))
		}
	}

	return &dnsgatev1.Response{Result: &dnsgatev1.Response_ListZones{ListZones: out}}, nil
}

// getZone reads one zone. The token needs get on zones for it.
func (g *Gateway) getZone(r *request, req *dnsgatev1.GetZoneRequest) (*dnsgatev1.Response, error) {
	c, err := g.startDNSCall(r, audit.EventZonesGet, req,
		permission.Request{Verb: permission.VerbGet, Resource: permission.ResourceZones, Zone: req.GetZone()}, checkZoneOf)
	if err != nil {
		return nil, err
	}

	z, err := c.provider.Zone(c.ctx, c.perm.Zone)
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
		Name:        dnsname.Zone(z.Name),
		State:       zoneStates[z.State],
		Nameservers: z.Nameservers,
	}
}
