package catalog_test

import (
	"maps"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

func TestEveryProviderOnboardsFields(t *testing.T) {
	for _, name := range catalog.Names() {
		if !catalog.Accepts(name, catalog.TypeFields) {
			t.Errorf("%s does not onboard a fields credential", name)
		}
	}

	if catalog.Accepts("route53", catalog.TypeFields) {
		t.Error("an unsupported Provider onboards a fields credential")
	}
}

func TestOnlyCloudflareOnboardsAnAPIToken(t *testing.T) {
	for _, name := range catalog.Names() {
		if got, want := catalog.Accepts(name, catalog.TypeAPIToken), name == catalog.Cloudflare; got != want {
			t.Errorf("Accepts(%s, api-token) = %v, want %v", name, got, want)
		}
	}
}

func TestAnAPITokenFillsTheCloudflareToken(t *testing.T) {
	m, err := catalog.DecodeCredential(catalog.Cloudflare, catalog.TypeAPIToken, "secret")
	if err != nil || !maps.Equal(m, map[string]string{"token": "secret"}) {
		t.Errorf("DecodeCredential = %v, %v, want the token field", m, err)
	}
}

func TestFieldsRoundTrip(t *testing.T) {
	in := map[string]string{"key": "k", "secret": "s"}

	value, err := catalog.EncodeFields(catalog.GoDaddy, in)
	if err != nil {
		t.Fatalf("EncodeFields: %v", err)
	}

	out, err := catalog.DecodeCredential(catalog.GoDaddy, catalog.TypeFields, value)
	if err != nil || !maps.Equal(in, out) {
		t.Errorf("DecodeCredential = %v, %v, want %v", out, err, in)
	}
}

func TestFieldsRefuseUnknownAndEmpty(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"unknown": {"key": "k", "pasword": "SECRET"},
		"empty":   {"key": ""},
		"none":    {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := catalog.EncodeFields(catalog.InternetBS, m); err == nil {
				t.Error("EncodeFields: no error")
			} else if strings.Contains(err.Error(), "SECRET") {
				t.Errorf("error quotes a value: %v", err)
			}
		})
	}

	if _, err := catalog.DecodeCredential(catalog.Vultr, catalog.TypeFields, `"SECRET"`); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("DecodeCredential of a non-object = %v, want an error not quoting it", err)
	}
}

func TestSoleSecret(t *testing.T) {
	for name, want := range map[string]string{
		catalog.Cloudflare: "token",
		catalog.Scaleway:   "secret_key",
		catalog.Vultr:      "api_key",
		catalog.GoDaddy:    "",
		catalog.ClouDNS:    "",
		"route53":          "",
	} {
		if got, ok := catalog.SoleSecret(name); got != want || ok != (want != "") {
			t.Errorf("SoleSecret(%s) = %q, %v, want %q", name, got, ok, want)
		}
	}
}
