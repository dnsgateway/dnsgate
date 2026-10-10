// Package catalog names the Providers the Gateway supports and the type of
// the Provider Credential each onboards. It links no Provider
// implementation, so clients can import it without them.
package catalog

import (
	"maps"
	"slices"
)

// Cloudflare is the name of the Cloudflare Provider.
const Cloudflare = "cloudflare"

// credentialTypes maps each supported Provider to the type of its
// Provider Credential.
var credentialTypes = map[string]string{
	Cloudflare: "api-token",
}

// Names returns the names of the supported Providers, sorted.
func Names() []string {
	return slices.Sorted(maps.Keys(credentialTypes))
}

// CredentialType returns the type of the Provider Credential onboarded for
// the Provider name, and whether name is a supported Provider.
func CredentialType(name string) (string, bool) {
	typ, ok := credentialTypes[name]

	return typ, ok
}
