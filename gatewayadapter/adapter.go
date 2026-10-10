package gatewayadapter

import (
	"context"
	"errors"
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

	// inspecting is held while the token is inspected for its Provider
	// type.
	inspecting sync.Mutex

	mu sync.Mutex
	// typ is the Factory of the token's Provider type, once known; the
	// zero Factory when the Gateway did not name a type a.providers holds.
	typ *dnsprovider.Factory
}

var (
	_ dnsprovider.Provider  = (*adapter)(nil)
	_ dnsprovider.Batcher   = (*adapter)(nil)
	_ dnsprovider.TTLLimits = (*adapter)(nil)
	_ dnsprovider.AutoTTL   = (*adapter)(nil)
	_ dnsprovider.ProxyFlag = (*adapter)(nil)
)

// inspectTimeout bounds the InspectToken call that learns the token's
// Provider type.
const inspectTimeout = 10 * time.Second

// learnProvider keeps the Factory of the token's Provider type name, as
// InspectToken names it: the zero Factory for a type a.providers does not
// hold, which stays unknown.
func (a *adapter) learnProvider(name string) {
	f := a.providers[name]

	a.mu.Lock()
	defer a.mu.Unlock()

	a.typ = &f
}

// providerType returns the Factory of the token's Provider type,
// inspecting the token the first time, unless Account did, for at most
// inspectTimeout. While the type is not known, it is the zero Factory:
// the default TTL range and no Record Extras.
//
// The answer is kept once the Gateway gives one: the type, an unknown
// type, or a refusal of the token, which the Gateway gives again for as
// long as the token lives. Only a call that got no answer from the
// Gateway, such as when it cannot be reached, is retried by the next.
func (a *adapter) providerType(ctx context.Context) dnsprovider.Factory {
	if typ, ok := a.knownType(); ok {
		return typ
	}

	// One inspection at a time: concurrent callers wait for its answer.
	a.inspecting.Lock()
	defer a.inspecting.Unlock()

	if typ, ok := a.knownType(); ok {
		return typ
	}

	ctx, cancel := context.WithTimeout(ctx, inspectTimeout)
	defer cancel()

	inspected, err := a.client.InspectToken(ctx, a.token)
	if err == nil {
		a.learnProvider(inspected.GetProvider())
	} else if answered(err) {
		a.learnProvider("")
	}

	typ, _ := a.knownType()

	return typ
}

// knownType returns the Factory of the token's Provider type, and
// whether it is known yet.
func (a *adapter) knownType() (dnsprovider.Factory, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.typ == nil {
		return dnsprovider.Factory{}, false
	}

	return *a.typ, true
}

// answered reports whether err, of a Gateway call, is the Gateway's
// answer, one with a Gateway error detail, not a failure to reach it.
func answered(err error) bool {
	gwErr, ok := errors.AsType[*client.Error](err)

	return ok && gwErr.Detail() != nil
}

// TTLRange implements dnsprovider.TTLLimits: the TTL range of the token's
// Provider type.
func (a *adapter) TTLRange() (minTTL, maxTTL uint32) {
	r := a.providerType(context.Background()).TTLRange()

	return r.Min, r.Max
}

// AutoTTL implements dnsprovider.AutoTTL: whether the token's Provider
// type reads TTL 1 as automatic.
func (a *adapter) AutoTTL() bool {
	return a.providerType(context.Background()).TTLRange().Auto
}

// ProxiableTypes implements dnsprovider.ProxyFlag: the Record types the
// token's Provider type can proxy, none for one that proxies nothing.
func (a *adapter) ProxiableTypes() []string {
	return a.providerType(context.Background()).ProxiableTypes()
}
