package provider_test

import (
	"slices"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/provider"
)

func TestRegistryOffersCloudflareOnly(t *testing.T) {
	types := provider.Registry().Types()

	if want := []string{provider.Cloudflare}; !slices.Equal(types, want) {
		t.Errorf("Registry offers %v, want %v", types, want)
	}

	for _, absent := range []string{"godaddy", "namecheap"} {
		if slices.Contains(types, absent) {
			t.Errorf("Registry offers %q, want it left out", absent)
		}
	}
}

func TestEveryProviderHasACredentialType(t *testing.T) {
	for _, name := range provider.Names() {
		if _, ok := provider.CredentialType(name); !ok {
			t.Errorf("Provider %q has no credential type", name)
		}
	}

	if got, _ := provider.CredentialType(provider.Cloudflare); got != "api-token" {
		t.Errorf("Cloudflare credential type = %q, want api-token", got)
	}

	if _, ok := provider.CredentialType("godaddy"); ok {
		t.Error("an unsupported Provider has a credential type")
	}
}

func TestEveryProviderBuildsFromItsCredentialFields(t *testing.T) {
	for _, name := range provider.Names() {
		if _, err := provider.Registry().New(name, provider.CredentialFields(name, "credential")); err != nil {
			t.Errorf("Provider %q does not build from its credential fields: %v", name, err)
		}
	}
}
