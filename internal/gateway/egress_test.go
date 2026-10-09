package gateway_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/provider"
)

// cloudflareHost is where the Cloudflare Provider sends its requests.
const cloudflareHost = "api.cloudflare.com"

// fakeCloudflare is a scripted Cloudflare v4 API, served over TLS and
// reached through the Gateway's Egress Transport in place of
// api.cloudflare.com.
type fakeCloudflare struct {
	zones   []map[string]any
	records map[string][]map[string]any // by zone ID
	// fail, when set, answers every request instead of the scripted data.
	fail http.HandlerFunc

	mu sync.Mutex
	// seen records each request's host and Authorization header.
	seen []seenRequest
	// dialed records each address the Egress Transport dialed.
	dialed []string
}

type seenRequest struct {
	host, authorization string
}

// newCloudflareHarness returns a harness whose Gateway runs the real
// Cloudflare Provider, its Egress Transport pointed at a fake Cloudflare
// API scripted with example.com.
func newCloudflareHarness(t *testing.T) (*harness, *fakeCloudflare) {
	t.Helper()

	cf := &fakeCloudflare{
		zones: []map[string]any{
			cfZone("z-com", "example.com", "active"),
			cfZone("z-org", "example.org", "pending"),
		},
		records: map[string][]map[string]any{
			"z-com": {
				cfRecord("r1", "A", "example.com", "192.0.2.1", 300),
				cfRecord("r2", "A", "www.apps.example.com", "192.0.2.10", 300),
				cfRecord("r3", "A", "www.apps.example.com", "192.0.2.11", 120),
				cfRecord("r4", "TXT", "_acme-challenge.www.example.com", `"abc"`, 60),
			},
		},
	}

	srv := httptest.NewTLSServer(cf.handler())
	t.Cleanup(srv.Close)

	h := newHarness(t)
	h.providers = provider.Registry()
	h.egress = cf.transport(t, srv)
	h.serve(t, h.keys)

	return h, cf
}

// transport is an Egress Transport that dials srv for every address and
// verifies its certificate strictly: it trusts srv's test CA alone, and
// checks the name srv's certificate is issued for.
func (cf *fakeCloudflare) transport(t *testing.T, srv *httptest.Server) http.RoundTripper {
	t.Helper()

	tr, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("test server transport is %T", srv.Client().Transport)
	}

	tr = tr.Clone()
	tr.TLSClientConfig.ServerName = "example.com" // in httptest's certificate

	dialer := &net.Dialer{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cf.mu.Lock()
		cf.dialed = append(cf.dialed, addr)
		cf.mu.Unlock()

		return dialer.DialContext(ctx, network, srv.Listener.Addr().String())
	}

	return tr
}

func (cf *fakeCloudflare) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /client/v4/zones", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")

		var out []map[string]any

		for _, z := range cf.zones {
			zone, _ := z["name"].(string)
			if text, ok := strings.CutPrefix(name, "contains:"); ok && strings.Contains(zone, text) || name == "" || zone == name {
				out = append(out, z)
			}
		}

		writeCFList(w, out)
	})
	mux.HandleFunc("GET /client/v4/zones/{zone}/dns_records", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		var out []map[string]any

		for _, rec := range cf.records[r.PathValue("zone")] {
			typ, _ := rec["type"].(string)
			name, _ := rec["name"].(string)

			if (!q.Has("type") || typ == q.Get("type")) && strings.Contains(name, strings.ToLower(q.Get("name.contains"))) {
				out = append(out, rec)
			}
		}

		writeCFList(w, out)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cf.mu.Lock()
		cf.seen = append(cf.seen, seenRequest{host: r.Host, authorization: r.Header.Get("Authorization")})
		cf.mu.Unlock()

		if cf.fail != nil {
			cf.fail(w, r)

			return
		}

		mux.ServeHTTP(w, r)
	})
}

func cfZone(id, name, state string) map[string]any {
	return map[string]any{
		"id":           id,
		"name":         name,
		"status":       state,
		"type":         "full",
		"name_servers": []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"},
	}
}

func cfRecord(id, typ, name, content string, ttl int) map[string]any {
	return map[string]any{"id": id, "type": typ, "name": name, "content": content, "ttl": ttl}
}

func writeCFList(w http.ResponseWriter, result []map[string]any) {
	if result == nil {
		result = []map[string]any{}
	}

	writeCF(w, http.StatusOK, map[string]any{
		"success": true, "errors": []any{}, "messages": []any{}, "result": result,
		"result_info": map[string]any{"page": 1, "per_page": len(result), "count": len(result), "total_count": len(result), "total_pages": 1},
	})
}

func writeCFError(w http.ResponseWriter, status, code int, message string) {
	writeCF(w, status, map[string]any{
		"success": false, "errors": []any{map[string]any{"code": code, "message": message}}, "messages": []any{}, "result": nil,
	})
}

func writeCF(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestGatewayEgressReadsCloudflare(t *testing.T) {
	h, cf := newCloudflareHarness(t)

	root := h.onboard(t, onboardRequest())

	zones, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root})
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}

	if got := zoneNames(zones.GetZones()); !slices.Equal(got, []string{"example.com", "example.org"}) {
		t.Errorf("zones = %v, want example.com and example.org", got)
	}

	zone, err := h.client.GetZone(t.Context(), &dnsgatev1.GetZoneRequest{Token: root, Zone: "example.com"})
	if err != nil {
		t.Fatalf("GetZone: %v", err)
	}

	if z := zone.GetZone(); z.GetState() != dnsgatev1.Zone_STATE_ACTIVE || len(z.GetNameservers()) != 2 {
		t.Errorf("zone = %v, want example.com, active, with its nameservers", z)
	}

	records, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: root, Zone: "example.com"})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	want := []string{"@ A 300 192.0.2.1", `_acme-challenge.www TXT 60 "abc"`, "www.apps A 120 192.0.2.10,192.0.2.11"}
	if got := recordSets(records.GetRecordSets()); !slices.Equal(got, want) {
		t.Errorf("record sets =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	record, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: root, Zone: "example.com", Name: "www.apps", Type: "A"})
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if got := recordSets([]*dnsgatev1.RecordSet{record.GetRecordSet()}); got[0] != want[2] {
		t.Errorf("record set = %q, want %q", got[0], want[2])
	}

	// The Provider Credential went to Cloudflare alone.
	cf.mu.Lock()
	defer cf.mu.Unlock()

	if len(cf.seen) == 0 {
		t.Fatal("Cloudflare got no request")
	}

	for _, r := range cf.seen {
		if r.host != cloudflareHost || r.authorization != "Bearer "+cfToken {
			t.Errorf("request to %s with Authorization %q, want %s with the Provider Credential", r.host, r.authorization, cloudflareHost)
		}
	}

	for _, addr := range cf.dialed {
		if addr != cloudflareHost+":443" {
			t.Errorf("Egress Transport dialed %s, want %s:443 alone", addr, cloudflareHost)
		}
	}
}

func TestGatewayEgressMapsCloudflareErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		fail     http.HandlerFunc
		zone     string
		code     codes.Code
		category dnsgatev1.Error_Category
		status   int32
	}{
		"forbidden": {
			func(w http.ResponseWriter, _ *http.Request) {
				writeCFError(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
			},
			"example.com", codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, 403,
		},
		"bad token answered with 400": {
			func(w http.ResponseWriter, _ *http.Request) {
				writeCFError(w, http.StatusBadRequest, 6003, "Invalid request headers")
			},
			"example.com", codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, 400,
		},
		"rate limited": {
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "60")
				writeCFError(w, http.StatusTooManyRequests, 971, "Please wait and consider throttling your request speed")
			},
			"example.com", codes.ResourceExhausted, dnsgatev1.Error_CATEGORY_RATE_LIMITED, 429,
		},
		// Cloudflare answers a zone it lacks with an empty list: the
		// Provider reports it not found without an HTTP status.
		"zone unknown to Cloudflare": {
			nil, "example.net", codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND, 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, cf := newCloudflareHarness(t)
			cf.fail = tc.fail

			root := h.onboard(t, onboardRequest())

			for _, req := range []any{
				&dnsgatev1.GetZoneRequest{Zone: tc.zone},
				&dnsgatev1.ListRecordsRequest{Zone: tc.zone},
				&dnsgatev1.GetRecordRequest{Zone: tc.zone, Name: "www.apps", Type: "A"},
			} {
				err := h.call(t, root, req)
				wantError(t, err, tc.code, tc.category)

				if got := dnsgatev1.ErrorDetail(status.Convert(err)).GetProviderStatus(); got != tc.status {
					t.Errorf("provider status = %d, want %d", got, tc.status)
				}
			}

			for _, e := range h.auditEvents(t)[1:] {
				if e["result"] != "failed" || e["category"] != tc.category.Name() || e["provider_status"] != statusField(tc.status) {
					t.Errorf("audit event = %v, want failed, category %s, provider status %d", e, tc.category.Name(), tc.status)
				}
			}
		})
	}
}

// statusField is a provider_status as an audit event decodes it: absent
// when zero.
func statusField(s int32) any {
	if s == 0 {
		return nil
	}

	return float64(s)
}
