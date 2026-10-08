// Package provider picks the Providers the Gateway supports from the
// shared dnsprovider module.
package provider

import (
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// Cloudflare is the Registry key of the Cloudflare Provider.
const Cloudflare = "cloudflare"

// Registry returns the Providers whose Provider Credentials can be
// onboarded into the Gateway, keyed by the Provider's name. v1 supports
// Cloudflare alone.
func Registry() dnsprovider.Registry {
	return dnsprovider.Registry{
		Cloudflare: cloudflare.Factory(),
	}
}
