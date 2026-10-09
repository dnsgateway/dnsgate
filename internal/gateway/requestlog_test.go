package gateway_test

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc/codes"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/token"
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

func TestARequestLineCarriesTheRequestIDOfItsAuditEvent(t *testing.T) {
	h := newDebugHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	// A successful read writes no audit event; a denied one does.
	if _, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root + "x"}); err == nil {
		t.Fatal("ListZones with a tampered token succeeded")
	}

	events, lines := h.auditEvents(t), h.requestLines(t)
	if len(events) != 2 || len(lines) != 2 {
		t.Fatalf("audit events = %v, request lines = %v, want two of each", events, lines)
	}

	for i := range events {
		if lines[i]["request_id"] != events[i]["request_id"] {
			t.Errorf("request line %d request_id = %v, want %v, its audit event's", i, lines[i]["request_id"], events[i]["request_id"])
		}
	}

	if lines[0]["request_id"] == lines[1]["request_id"] {
		t.Errorf("both requests are logged with request_id %v", lines[0]["request_id"])
	}
}

func TestDeniedAndFailedRequestsAreLoggedWithTheirCode(t *testing.T) {
	h := newDebugHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())
	reader := h.mint(t, nil, token.Permission{
		Verbs: []string{"get"}, Zones: []string{"example.com"}, Names: []string{"www"}, Types: []string{"A"}, Egress: []string{"gateway"},
	})

	wrongSecret := onboardRequest()
	wrongSecret.BootstrapSecret = "wrong"

	_, err := h.client.Onboard(t.Context(), wrongSecret)
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	err = h.call(t, root+"x", &dnsgatev1.ListZonesRequest{})
	wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

	err = h.call(t, reader, &dnsgatev1.ListZonesRequest{})
	wantError(t, err, codes.PermissionDenied, dnsgatev1.Error_CATEGORY_PERMISSION_DENIED)

	h.fake.Fail(providertest.OpZone, &dnsprovider.APIError{Provider: "cloudflare", StatusCode: 500})

	err = h.call(t, root, &dnsgatev1.GetZoneRequest{Zone: "example.com"})
	wantError(t, err, codes.Unavailable, dnsgatev1.Error_CATEGORY_INTERNAL)

	stream, err := h.api.Call(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}

	_, err = stream.Recv()
	wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)

	want := []struct{ operation, code string }{
		{"onboard", "OK"},
		{"onboard", "Unauthenticated"},
		{"list_zones", "Unauthenticated"},
		{"list_zones", "PermissionDenied"},
		{"get_zone", "Unavailable"},
		{"", "InvalidArgument"},
	}

	lines := h.requestLines(t)
	if len(lines) != len(want) {
		t.Fatalf("request lines = %v, want %d", lines, len(want))
	}

	for i, w := range want {
		l := lines[i]

		if op, _ := l["operation"].(string); op != w.operation || l["code"] != w.code {
			t.Errorf("request line %d = %v, want operation %q, code %s", i, l, w.operation, w.code)
		}

		if id, _ := l["request_id"].(string); !strings.HasPrefix(id, "req_") {
			t.Errorf("request line %d request_id = %v, want a req_ ID", i, l["request_id"])
		}
	}
}

// TestRequestLinesCarryNoSecrets sends requests carrying the Bootstrap
// Secret, the Provider Credential and Service Tokens, successful and
// refused, and checks that no request line carries any of them.
func TestRequestLinesCarryNoSecrets(t *testing.T) {
	h := newDebugHarness(t)
	h.addZones()

	root := h.onboard(t, onboardRequest())

	wrongSecret := onboardRequest()
	wrongSecret.BootstrapSecret = bootstrapSecret + "x"

	if _, err := h.client.Onboard(t.Context(), wrongSecret); err == nil {
		t.Fatal("onboard with a wrong bootstrap secret succeeded")
	}

	if err := h.call(t, root, &dnsgatev1.ListZonesRequest{}); err != nil {
		t.Fatalf("ListZones: %v", err)
	}

	if err := h.call(t, root+"x", &dnsgatev1.ListZonesRequest{}); err == nil {
		t.Fatal("ListZones with a tampered token succeeded")
	}

	if _, err := h.client.InspectToken(t.Context(), root); err != nil {
		t.Fatalf("InspectToken: %v", err)
	}

	if lines := h.requestLines(t); len(lines) != 5 {
		t.Fatalf("request lines = %v, want 5", lines)
	}

	logs := h.logs.String()

	for name, secret := range map[string]string{
		"Bootstrap Secret":    bootstrapSecret,
		"Provider Credential": cfToken,
		"Service Token":       root,
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs carry the %s:\n%s", name, logs)
		}
	}
}
