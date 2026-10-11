package gatewayadapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

// endings are the errors a context ends with, by how it ends.
var endings = map[string]error{"canceled": context.Canceled, "expired": context.DeadlineExceeded}

// endedContext returns a context that ended with want: canceled, or past
// its deadline.
func endedContext(t *testing.T, want error) context.Context {
	t.Helper()

	if want == context.Canceled {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		return ctx
	}

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)

	return ctx
}

func TestAReadWhoseContextEndedFailsWithTheContextsError(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.root)

	for name, want := range endings {
		t.Run(name, func(t *testing.T) {
			_, err := p.ListZones(endedContext(t, want), dnsprovider.ZoneFilter{})
			if !errors.Is(err, want) {
				t.Errorf("Zones = %v, want %v", err, want)
			}

			if _, ok := errors.AsType[*dnsprovider.APIError](err); ok {
				t.Errorf("Zones = %v, want no API error", err)
			}
		})
	}
}

func TestAWriteWhoseContextEndedFailsWithTheContextsError(t *testing.T) {
	h := newHarness(t)
	h.fake.SetRecords("z1", wwwRecords()...)

	p := h.provider(t, h.root)
	z := zone(t, p)

	for name, want := range endings {
		t.Run(name, func(t *testing.T) {
			_, err := p.CreateRecord(endedContext(t, want), z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.3", TTL: 300})
			if !errors.Is(err, want) {
				t.Errorf("CreateRecord = %v, want %v", err, want)
			}

			if _, ok := errors.AsType[*dnsprovider.APIError](err); ok || strings.Contains(err.Error(), "reading the RRset") {
				t.Errorf("CreateRecord = %v, want neither an API error nor an RRset read failure", err)
			}
		})
	}
}
