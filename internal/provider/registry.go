// Package provider picks the Providers the Gateway supports from the
// shared dnsprovider module.
package provider

import (
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"

	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

// Cloudflare is the Registry key of the Cloudflare Provider.
const Cloudflare = catalog.Cloudflare

// credentialFields maps each supported Provider to the field of its
// Factory the Provider Credential value fills.
var credentialFields = map[string]string{
	Cloudflare: cloudflare.FieldToken,
}

// Registry returns the Providers whose Provider Credentials can be
// onboarded into the Gateway, keyed by the Provider's name. v1 supports
// Cloudflare alone.
func Registry() dnsprovider.Registry {
	return dnsprovider.Registry{
		Cloudflare: cloudflare.Factory(),
	}
}

// Names returns the names of the supported Providers, sorted.
func Names() []string {
	return catalog.Names()
}

// CredentialFields returns the fields the Provider name is built from
// with the Provider Credential value. The map holds the plaintext
// credential: drop it with the Provider built from it.
func CredentialFields(name, value string) map[string]string {
	field, ok := credentialFields[name]
	if !ok {
		return nil
	}

	return map[string]string{field: value}
}

// CredentialType returns the type of the Provider Credential onboarded for
// the Provider name, and whether name is a supported Provider.
func CredentialType(name string) (string, bool) {
	return catalog.CredentialType(name)
}
