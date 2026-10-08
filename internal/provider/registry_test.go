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
