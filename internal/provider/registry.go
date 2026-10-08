// Package provider picks the DNS Providers the Gateway supports from the
// shared dnsprovider module.
package provider

import (
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// Registry returns the Providers the Gateway can be onboarded to, by
// Provider type. v1 supports Cloudflare alone.
func Registry() dnsprovider.Registry {
	return dnsprovider.Registry{
		"cloudflare": cloudflare.Factory(),
	}
}
