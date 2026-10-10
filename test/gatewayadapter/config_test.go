package gatewayadapter_test

import (
	"crypto/x509"
	"testing"

	"github.com/dnsgateway/dnsgate-go/gatewayadapter"
	"github.com/dnsgateway/dnsprovider"
)

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
