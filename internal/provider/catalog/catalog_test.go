package catalog_test

import (
	"slices"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

func TestCatalogNamesCloudflareOnly(t *testing.T) {
	if got, want := catalog.Names(), []string{"cloudflare"}; !slices.Equal(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
}

func TestCloudflareOnboardsAnAPIToken(t *testing.T) {
	if got, ok := catalog.CredentialType(catalog.Cloudflare); !ok || got != "api-token" {
		t.Errorf("CredentialType(cloudflare) = %q, %v, want api-token, true", got, ok)
	}

	if _, ok := catalog.CredentialType("godaddy"); ok {
		t.Error("an unsupported Provider has a credential type")
	}
}
