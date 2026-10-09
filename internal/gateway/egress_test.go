package gateway_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// cloudflareHost is where the Cloudflare Provider sends its requests.
const cloudflareHost = "api.cloudflare.com"

// fakeCloudflare is a scripted Cloudflare v4 API, served over TLS and
// reached in place of api.cloudflare.com.
type fakeCloudflare struct {
	zones   []map[string]any
	records map[string][]map[string]any // by zone ID
	// fail, when set, answers every request instead of the scripted data.
	fail http.HandlerFunc

	mu sync.Mutex
	// seen records each request's host and Authorization header.
	seen []seenRequest
	// dialed records each address Gateway Egress dialed.
	dialed []string
	// nextID numbers the records created.
	nextID int
}

type seenRequest struct {
	method, host, authorization string
}

// record returns the record id of zone, nil if it has none. The caller
// holds cf.mu.
func (cf *fakeCloudflare) record(zone, id string) map[string]any {
	for _, rec := range cf.records[zone] {
		if rec["id"] == id {
			return rec
		}
	}

	return nil
}

// newCloudflareHarness returns a harness whose Gateway runs the real
// Cloudflare Provider, its Gateway Egress pointed at a fake Cloudflare
// API scripted with example.com, presenting a trusted certificate.
func newCloudflareHarness(t *testing.T) (*harness, *fakeCloudflare) {
	t.Helper()

	cf := newFakeCloudflare()

	srv := cf.newServer(t, trustedCert)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	h := newHarness(t)
	h.reach(cf, srv)
	h.serve(t, h.keys)

	return h, cf
}

// newFakeCloudflare returns a fake Cloudflare API scripted with
// example.com and example.org.
func newFakeCloudflare() *fakeCloudflare {
	return &fakeCloudflare{
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

		cf.mu.Lock()
		defer cf.mu.Unlock()

		for _, rec := range cf.records[r.PathValue("zone")] {
			typ, _ := rec["type"].(string)
			name, _ := rec["name"].(string)

			if (!q.Has("type") || typ == q.Get("type")) && strings.Contains(name, strings.ToLower(q.Get("name.contains"))) {
				out = append(out, rec)
			}
		}

		writeCFList(w, out)
	})

	mux.HandleFunc("POST /client/v4/zones/{zone}/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var rec map[string]any
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			writeCFError(w, http.StatusBadRequest, 9207, "Request body is invalid")

			return
		}

		zone := r.PathValue("zone")

		cf.mu.Lock()
		cf.nextID++
		rec["id"] = fmt.Sprintf("new%d", cf.nextID)
		cf.records[zone] = append(cf.records[zone], rec)
		cf.mu.Unlock()

		writeCF(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": rec})
	})
	mux.HandleFunc("PATCH /client/v4/zones/{zone}/dns_records/{id}", func(w http.ResponseWriter, r *http.Request) {
		var edit map[string]any
		if err := json.NewDecoder(r.Body).Decode(&edit); err != nil {
			writeCFError(w, http.StatusBadRequest, 9207, "Request body is invalid")

			return
		}

		cf.mu.Lock()
		rec := cf.record(r.PathValue("zone"), r.PathValue("id"))
		if rec != nil {
			maps.Copy(rec, edit)
		}
		cf.mu.Unlock()

		if rec == nil {
			writeCFError(w, http.StatusNotFound, 81044, "Record does not exist.")

			return
		}

		writeCF(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": rec})
	})
	mux.HandleFunc("DELETE /client/v4/zones/{zone}/dns_records/{id}", func(w http.ResponseWriter, r *http.Request) {
		zone, id := r.PathValue("zone"), r.PathValue("id")

		cf.mu.Lock()
		n := len(cf.records[zone])
		cf.records[zone] = slices.DeleteFunc(cf.records[zone], func(rec map[string]any) bool { return rec["id"] == id })
		deleted := len(cf.records[zone]) < n
		cf.mu.Unlock()

		if !deleted {
			writeCFError(w, http.StatusNotFound, 81044, "Record does not exist.")

			return
		}

		writeCF(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"id": id}})
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cf.mu.Lock()
		cf.seen = append(cf.seen, seenRequest{method: r.Method, host: r.Host, authorization: r.Header.Get("Authorization")})
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
		t.Errorf("RRsets =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	record, err := h.client.GetRecord(t.Context(), &dnsgatev1.GetRecordRequest{Token: root, Zone: "example.com", Name: "www.apps", Type: "A"})
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if got := recordSets([]*dnsgatev1.RecordSet{record.GetRecordSet()}); got[0] != want[2] {
		t.Errorf("RRset = %q, want %q", got[0], want[2])
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
			t.Errorf("Gateway Egress dialed %s, want %s:443 alone", addr, cloudflareHost)
		}
	}
}

func TestGatewayEgressChangesCloudflareRecords(t *testing.T) {
	h, cf := newCloudflareHarness(t)

	root := h.onboard(t, onboardRequest())

	if _, err := h.client.PatchRecord(t.Context(), &dnsgatev1.PatchRecordRequest{
		Token: root, Zone: "example.com", Name: "_acme-challenge.www", Type: "TXT", Add: []string{`"def"`},
	}); err != nil {
		t.Fatalf("PatchRecord: %v", err)
	}

	if _, err := h.client.UpdateRecord(t.Context(), &dnsgatev1.UpdateRecordRequest{
		Token: root, Zone: "example.com", Name: "www.apps", Type: "A", Ttl: 300, Values: []string{"192.0.2.10", "192.0.2.12"},
	}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	if _, err := h.client.DeleteRecord(t.Context(), &dnsgatev1.DeleteRecordRequest{
		Token: root, Zone: "example.com", Name: "@", Type: "A",
	}); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	if _, err := h.client.CreateRecord(t.Context(), &dnsgatev1.CreateRecordRequest{
		Token: root, Zone: "example.com", Name: "api", Type: "AAAA", Ttl: 120, Values: []string{"2001:db8::1"},
	}); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	records, err := h.client.ListRecords(t.Context(), &dnsgatev1.ListRecordsRequest{Token: root, Zone: "example.com"})
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}

	var got []string
	for _, s := range records.GetRecordSets() {
		got = append(got, sortedSet(s))
	}

	want := []string{`_acme-challenge.www TXT 60 "abc","def"`, "api AAAA 120 2001:db8::1", "www.apps A 300 192.0.2.10,192.0.2.12"}
	if !slices.Equal(got, want) {
		t.Errorf("RRsets =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	cf.mu.Lock()
	defer cf.mu.Unlock()

	var writes []string

	for _, r := range cf.seen {
		if r.method != http.MethodGet {
			writes = append(writes, r.method)
		}

		if r.host != cloudflareHost || r.authorization != "Bearer "+cfToken {
			t.Errorf("request to %s with Authorization %q, want %s with the Provider Credential", r.host, r.authorization, cloudflareHost)
		}
	}

	// One call per change: the patch's addition, the update's
	// modification of 192.0.2.11, the deletion and the creation.
	if wantWrites := []string{http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodPost}; !slices.Equal(writes, wantWrites) {
		t.Errorf("writes = %v, want %v", writes, wantWrites)
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
