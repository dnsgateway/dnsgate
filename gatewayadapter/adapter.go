package gatewayadapter

import (
	"context"
	"sync"
	"time"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
)

// adapter is the Gateway Adapter: a dnsprovider.Provider whose every call
// is one Gateway request.
type adapter struct {
	client *client.Client
	token  string
	egress dnsgatev1.Egress
	// providers are the Provider types the token's Provider is looked up
	// in.
	providers dnsprovider.Registry

	mu sync.Mutex
	// typ is the Factory of the token's Provider type, once known.
	typ *dnsprovider.Factory
}

var (
	_ dnsprovider.Provider  = (*adapter)(nil)
	_ dnsprovider.Batcher   = (*adapter)(nil)
	_ dnsprovider.TTLLimits = (*adapter)(nil)
	_ dnsprovider.AutoTTL   = (*adapter)(nil)
	_ dnsprovider.ProxyFlag = (*adapter)(nil)
)

func (a *adapter) CreateRecord(context.Context, dnsprovider.Zone, dnsprovider.Record) (dnsprovider.Record, error) {
	return dnsprovider.Record{}, dnsprovider.ErrNotImplemented
}

func (a *adapter) UpdateRecord(context.Context, dnsprovider.Zone, dnsprovider.Record, dnsprovider.Record) (dnsprovider.Record, error) {
	return dnsprovider.Record{}, dnsprovider.ErrNotImplemented
}

func (a *adapter) DeleteRecord(context.Context, dnsprovider.Zone, dnsprovider.Record) error {
	return dnsprovider.ErrNotImplemented
}

func (a *adapter) ApplyChangeset(context.Context, dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	return dnsprovider.ApplyResult{}, dnsprovider.ErrNotImplemented
}

// inspectTimeout bounds the InspectToken call that learns the token's
// Provider type for the methods that take no context.
const inspectTimeout = 10 * time.Second

// learnProvider keeps the Factory of the token's Provider type name, as
// InspectToken names it. A type a.providers does not hold leaves it
// unknown.
func (a *adapter) learnProvider(name string) {
	f, ok := a.providers[name]
	if !ok {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.typ = &f
}

// providerType returns the Factory of the token's Provider type,
// inspecting the token the first time, unless Account did. While the
// type is not known, such as when the Gateway cannot be reached, it is
// the zero Factory: the default TTL range and no Record Extras.
func (a *adapter) providerType() dnsprovider.Factory {
	a.mu.Lock()
	typ := a.typ
	a.mu.Unlock()

	if typ != nil {
		return *typ
	}

	ctx, cancel := context.WithTimeout(context.Background(), inspectTimeout)
	defer cancel()

	if inspected, err := a.client.InspectToken(ctx, a.token); err == nil {
		a.learnProvider(inspected.GetProvider())
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.typ == nil {
		return dnsprovider.Factory{}
	}

	return *a.typ
}

// TTLRange implements dnsprovider.TTLLimits: the TTL range of the token's
// Provider type.
func (a *adapter) TTLRange() (minTTL, maxTTL uint32) {
	r := a.providerType().TTLRange()

	return r.Min, r.Max
}

// AutoTTL implements dnsprovider.AutoTTL: whether the token's Provider
// type reads TTL 1 as automatic.
func (a *adapter) AutoTTL() bool {
	return a.providerType().TTLRange().Auto
}

// ProxiableTypes implements dnsprovider.ProxyFlag: the Record types the
// token's Provider type can proxy, none for one that proxies nothing.
func (a *adapter) ProxiableTypes() []string {
	return a.providerType().ProxiableTypes()
}
