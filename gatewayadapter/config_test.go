package gatewayadapter_test

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"

	"github.com/dnsgateway/dnsgate/gatewayadapter"
)

func TestFactoryDeclaresGatewayTokenAndEgress(t *testing.T) {
	f := gatewayadapter.Factory()

	want := []dnsprovider.Field{
		{Name: "gateway", Label: "Gateway address"},
		{Name: "token", Label: "Service Token", Secret: true},
		{Name: "egress", Label: "Egress", Default: "auto", Choices: []string{"auto", "gateway", "agent"}},
	}

	if !slices.EqualFunc(f.Fields, want, func(a, b dnsprovider.Field) bool {
		return a.Name == b.Name && a.Label == b.Label && a.Secret == b.Secret && a.Tenant == b.Tenant &&
			a.Default == b.Default && slices.Equal(a.Choices, b.Choices)
	}) {
		t.Errorf("Fields = %+v, want %+v", f.Fields, want)
	}

	if len(f.Capabilities) != 0 {
		t.Errorf("Capabilities = %v, want none: the Gateway has no Zone writes", f.Capabilities)
	}
}

func TestNewMakesNoNetworkCall(t *testing.T) {
	// Nothing listens on port 1: building succeeds all the same.
	p, err := gatewayadapter.Factory().New(map[string]string{"gateway": "127.0.0.1:1", "token": "tok"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if p == nil {
		t.Fatal("New returned no Provider")
	}

	if _, ok := p.(dnsprovider.Batcher); !ok {
		t.Error("the Gateway Adapter is no Batcher")
	}
}

func TestNewRefusesBadFields(t *testing.T) {
	for name, fields := range map[string]map[string]string{
		"unknown field":   {"gateway": "127.0.0.1:1", "token": "tok", "tokn": "x"},
		"missing token":   {"gateway": "127.0.0.1:1"},
		"missing gateway": {"token": "tok"},
		"unknown egress":  {"gateway": "127.0.0.1:1", "token": "tok", "egress": "direct"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := gatewayadapter.Factory().New(fields)
			if err == nil {
				t.Fatalf("New(%v) = %v, want an error", fields, p)
			}

			if p != nil {
				t.Errorf("New returned a Provider with its error: %v", p)
			}
		})
	}
}

func TestTrustInTheGatewayIsSetWhenTheGatewayAdapterIsBuilt(t *testing.T) {
	h := newHarness(t)
	pool := x509.NewCertPool()

	p, err := gatewayadapter.Factory(gatewayadapter.WithRootCAs(pool)).New(map[string]string{"gateway": h.addr, "token": h.root})
	if err != nil {
		t.Fatal(err)
	}

	// Trusting the Gateway's certificate afterwards changes nothing.
	pool.AddCert(h.cert)

	if _, err := p.Zones(t.Context(), dnsprovider.ZoneFilter{}); err == nil {
		t.Error("Zones succeeded, want the Gateway's certificate untrusted")
	}
}

func TestNewTakesEachEgress(t *testing.T) {
	for _, egress := range []string{"", "auto", "gateway", "agent"} {
		if _, err := gatewayadapter.Factory().New(map[string]string{"gateway": "127.0.0.1:1", "token": "tok", "egress": egress}); err != nil {
			t.Errorf("New with egress %q: %v", egress, err)
		}
	}
}
