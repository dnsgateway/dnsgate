package provider_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"

	"github.com/dnsgateway/dnsgate/internal/provider"
)

func TestRegistryOffersCloudflareOnly(t *testing.T) {
	if got, want := provider.Registry().Types(), []string{"cloudflare"}; !slices.Equal(got, want) {
		t.Errorf("Provider types = %v, want %v", got, want)
	}
}

func TestCloudflareSendsTheProviderCredentialAndMapsRejection(t *testing.T) {
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`))
	}))
	t.Cleanup(srv.Close)

	p, err := provider.Registry().New("cloudflare", map[string]string{"token": "cf-secret"},
		dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Zone(context.Background(), "example.com")
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("Zone error = %v, want ErrUnauthorized", err)
	}

	if gotAuth != "Bearer cf-secret" {
		t.Errorf("Authorization = %q, want the Bearer Provider Credential", gotAuth)
	}
}

func TestRegistryRejectsCloudflareWithoutToken(t *testing.T) {
	if _, err := provider.Registry().New("cloudflare", map[string]string{}); err == nil {
		t.Error("building Cloudflare without a token succeeded, want an error")
	}
}
