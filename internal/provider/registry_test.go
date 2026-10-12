package provider_test

import (
	"slices"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

func TestRegistryOffersEveryCatalogProvider(t *testing.T) {
	if types, names := provider.Registry().Types(), provider.Names(); !slices.Equal(types, names) {
		t.Errorf("Registry offers %v, but Names() = %v", types, names)
	}
}

func TestCatalogFieldsMatchTheFactories(t *testing.T) {
	for name, f := range provider.Registry() {
		fs, _ := catalog.Fields(name)

		if len(fs) != len(f.Fields) {
			t.Errorf("%s: catalog fields %+v, Factory fields %+v", name, fs, f.Fields)

			continue
		}

		for i, want := range f.Fields {
			if got := fs[i]; got.Name != want.Name || got.Label != want.Label || got.Secret != want.Secret {
				t.Errorf("%s: catalog field %+v, Factory field %+v", name, got, want)
			}
		}
	}
}

func TestCloudflareBuildsFromALegacyAPIToken(t *testing.T) {
	fields, err := provider.CredentialFields(provider.Cloudflare, catalog.TypeAPIToken, "credential")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Registry().New(provider.Cloudflare, fields); err != nil {
		t.Errorf("Cloudflare does not build from an api-token credential: %v", err)
	}
}
