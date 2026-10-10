package gatewayadapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

// endedContexts are a canceled context and one past its deadline, with
// the error each ends with.
func endedContexts(t *testing.T) map[string]struct {
	ctx  context.Context
	want error
} {
	t.Helper()

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	expired, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	t.Cleanup(cancelExpired)

	return map[string]struct {
		ctx  context.Context
		want error
	}{
		"canceled": {canceled, context.Canceled},
		"expired":  {expired, context.DeadlineExceeded},
	}
}

func TestAReadWhoseContextEndedFailsWithTheContextsError(t *testing.T) {
	h := newHarness(t)
	p := h.provider(t, h.root)

	for name, tc := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			_, err := p.Zones(tc.ctx, dnsprovider.ZoneFilter{})
			if !errors.Is(err, tc.want) {
				t.Errorf("Zones = %v, want %v", err, tc.want)
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

	for name, tc := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			_, err := p.CreateRecord(tc.ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.3", TTL: 300})
			if !errors.Is(err, tc.want) {
				t.Errorf("CreateRecord = %v, want %v", err, tc.want)
			}

			if _, ok := errors.AsType[*dnsprovider.APIError](err); ok || strings.Contains(err.Error(), "reading the RRset") {
				t.Errorf("CreateRecord = %v, want neither an API error nor an RRset read failure", err)
			}
		})
	}
}
