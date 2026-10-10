package gatewayadapter

import "github.com/dnsgateway/dnsprovider"

// WithProviders makes the Factory's Gateway Adapters look the token's
// Provider type up in r, for tests whose Gateway calls a fake Provider.
func WithProviders(r dnsprovider.Registry) Option {
	return func(o *options) { o.providers = r }
}
