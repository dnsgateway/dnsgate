package gateway_test

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// newDebugHarness returns a harness whose Gateway logs at debug.
func newDebugHarness(t *testing.T) *harness {
	t.Helper()

	h := newHarness(t)
	h.logLevel = slog.LevelDebug
	h.serve(t, h.keys)

	return h
}

// requestLines decodes the Gateway's request log lines.
func (h *harness) requestLines(t *testing.T) []map[string]any {
	t.Helper()

	var lines []map[string]any

	for line := range strings.Lines(h.logs.String()) {
		var l map[string]any
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}

		if l["msg"] == "request" {
			lines = append(lines, l)
		}
	}

	return lines
}

func TestAtDebugARequestIsLoggedWithItsMethodIDPeerDurationAndCode(t *testing.T) {
	h := newDebugHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	if _, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root}); err != nil {
		t.Fatalf("ListZones: %v", err)
	}

	lines := h.requestLines(t)
	if len(lines) != 2 {
		t.Fatalf("request lines = %v, want one for the onboard and one for the zone list", lines)
	}

	l := lines[1]

	for field, want := range map[string]any{
		"level":       "DEBUG",
		"method":      "/dnsgate.v1.GatewayService/Call",
		"operation":   "list_zones",
		"peer":        "bufconn",
		"duration_ms": float64(0),
		"code":        "OK",
	} {
		if l[field] != want {
			t.Errorf("request line %s = %v, want %v", field, l[field], want)
		}
	}

	if id, _ := l["request_id"].(string); !strings.HasPrefix(id, "req_") {
		t.Errorf("request line request_id = %v, want a req_ ID", l["request_id"])
	}
}
