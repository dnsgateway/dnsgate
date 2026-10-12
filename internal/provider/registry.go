// Package provider picks the Providers the Gateway supports from the
// shared dnsprovider module.
package provider

import (
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers"

	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

// Cloudflare is the Registry key of the Cloudflare Provider.
const Cloudflare = catalog.Cloudflare

// Registry returns the Providers whose Provider Credentials can be
// onboarded into the Gateway, keyed by the Provider's name: every adapter
// of the dnsprovider module.
func Registry() dnsprovider.Registry {
	return providers.Registry()
}

// Names returns the names of the supported Providers, sorted.
func Names() []string {
	return catalog.Names()
}

// CredentialFields returns the fields the Provider name is built from
// with a Provider Credential of type typ and value. The map holds the
// plaintext credential: drop it with the Provider built from it. Errors
// never quote the credential.
func CredentialFields(name, typ, value string) (map[string]string, error) {
	return catalog.DecodeCredential(name, typ, value)
}
