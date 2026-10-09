// Package provider picks the Providers the Gateway supports from the
// shared dnsprovider module.
package provider

import (
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// Cloudflare is the Registry key of the Cloudflare Provider.
const Cloudflare = "cloudflare"

// credential is the Provider Credential onboarded for a Provider: its
// type, and the field of the Provider's Factory its value fills.
type credential struct {
	typ, field string
}

// credentials maps each supported Provider to its Provider Credential.
var credentials = map[string]credential{
	Cloudflare: {typ: "api-token", field: cloudflare.FieldToken},
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
	return Registry().Types()
}

// CredentialFields returns the fields the Provider name is built from
// with the Provider Credential value. The map holds the plaintext
// credential: drop it with the Provider built from it.
func CredentialFields(name, value string) map[string]string {
	c, ok := credentials[name]
	if !ok {
		return nil
	}

	return map[string]string{c.field: value}
}

// CredentialType returns the type of the Provider Credential onboarded for
// the Provider name, and whether name is a supported Provider.
func CredentialType(name string) (string, bool) {
	c, ok := credentials[name]

	return c.typ, ok
}
