package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

// acmeproxyCalls are the routes of the acmeproxy API, each with the
// values a call of challenge(1) at _acme-challenge.example.com finds
// there, presented beforehand, and the values it leaves.
var acmeproxyCalls = []struct {
	path        string
	seed, after []string
}{
	{"/present", []string{challenge(2)}, []string{challenge(1), challenge(2)}},
	{"/cleanup", []string{challenge(1), challenge(2)}, []string{challenge(2)}},
}

// txtAt60 is each of values as wantTXT wants it at the default TTL.
func txtAt60(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, `60 "`+v+`"`)
	}

	return out
}

// seeded starts a daemon with Gateway Egress and a token for
// _acme-challenge.example.com, and presents the values with it.
func (e *e2e) seeded(t *testing.T, values []string) (*acmeDaemon, acmeToken) {
	t.Helper()

	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for _, v := range values {
		d.wantPresented(t, tok, "_acme-challenge.example.com.", v)
	}

	return d, tok
}

// Unknown fields in the body are ignored, as in /update: the call is done
// and the reply echoes only the fqdn and the value.
func TestAcmeproxyIgnoresUnknownFields(t *testing.T) {
	for _, tc := range acmeproxyCalls {
		t.Run(tc.path, func(t *testing.T) {
			e := newE2E(t)
			d, tok := e.seeded(t, tc.seed)

			want := acmeproxyBody("_acme-challenge.example.com.", challenge(1))
			body := want[:len(want)-1] + `, "ttl": 300, "extra": {"a": [1]}}`

			if code, got := d.acmeproxy(t, tc.path, tok, body); code != http.StatusOK || !jsonEqual(got, want) {
				t.Fatalf("POST %s with unknown fields = %d %s, want 200 %s", tc.path, code, got, want)
			}

			e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", txtAt60(tc.after)...)
		})
	}
}

// A request without Basic auth, or without a password in it, is refused
// before any Gateway call, and the values stay as they were.
func TestAcmeproxyRefusesARequestWithoutBasicAuth(t *testing.T) {
	for _, tc := range acmeproxyCalls {
		t.Run(tc.path, func(t *testing.T) {
			e := newE2E(t)
			d, tok := e.seeded(t, tc.seed)

			const fqdn = "_acme-challenge.example.com."

			for name, cred := range map[string]acmeToken{
				"no Authorization header": {},
				"no password":             {User: tok.User},
			} {
				t.Run(name, func(t *testing.T) {
					e.gatewayUntouched(t, func() {
						entry := e.wantAcmeproxyForbiddenLogged(t, d, tc.path, cred, fqdn, "no Basic auth")
						wantLogged(t, entry, map[string]any{"name": fqdn}, "error")
					})
				})
			}

			e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", txtAt60(tc.seed)...)
		})
	}
}

// A username other than the token's jti, another token's or none, is
// refused, and logged for the same reason as an X-Api-User other than the
// jti. The values stay as they were.
func TestAcmeproxyRefusesAUsernameOtherThanTheTokenID(t *testing.T) {
	for _, tc := range acmeproxyCalls {
		t.Run(tc.path, func(t *testing.T) {
			e := newE2E(t)
			other := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
			d, tok := e.seeded(t, tc.seed)

			for name, user := range map[string]string{
				"another token's jti": other.User,
				"empty":               "",
			} {
				t.Run(name, func(t *testing.T) {
					e.wantAcmeproxyForbidden(t, d, tc.path, acmeToken{Key: tok.Key, User: user}, "_acme-challenge.example.com.",
						"X-Api-User is not the token's jti")
				})
			}

			e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", txtAt60(tc.seed)...)
		})
	}
}

func TestAcmeproxyIsAuditedAsAPatchByTheTokensServiceAccount(t *testing.T) {
	for _, tc := range acmeproxyCalls {
		t.Run(tc.path, func(t *testing.T) {
			e := newE2E(t)
			d, tok := e.seeded(t, tc.seed)

			audited := len(e.Gateway.Audit.String())

			d.wantEchoed(t, tc.path, tok, "_acme-challenge.example.com.", challenge(1))

			events := auditEvents(t, e.Gateway.Audit.String()[audited:], "records.patch")
			if len(events) != 1 {
				t.Fatalf("POST %s audited %d records.patch events, want 1:\n%s", tc.path, len(events), e.Gateway.Audit)
			}

			wantAuditedAsPatch(t, events[0])
		})
	}
}

func TestAcmeproxyLogsEachRequestWithoutTheTokenOrTheValue(t *testing.T) {
	for _, tc := range []struct {
		path string
		// at are the values at the fqdn before the calls: the ones the
		// calls remove, for /cleanup, so that it writes.
		at     []string
		writes providertest.Op
	}{
		{"/present", nil, providertest.OpCreateRecord},
		{"/cleanup", []string{challenge(1), challenge(3)}, providertest.OpDeleteRecord},
	} {
		t.Run(tc.path, func(t *testing.T) {
			e := newE2E(t)

			records := make([]dnsprovider.Record, 0, len(tc.at))
			for i, v := range tc.at {
				records = append(records, dnsprovider.Record{
					ID: "r" + strconv.Itoa(i), Type: "TXT", Name: "_acme-challenge.example.com", Value: `"` + v + `"`, TTL: 60,
				})
			}

			e.Fake.SetRecords(zoneComID, records...)

			tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
			refused := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
			d := e.acme(t, daemonConfig{Egress: "gateway"})

			const fqdn = "_acme-challenge.example.com."

			d.wantEchoed(t, tc.path, tok, fqdn, challenge(1))

			if code, body := d.acmeproxy(t, tc.path, refused, acmeproxyBody(fqdn, challenge(2))); code != http.StatusUnauthorized {
				t.Fatalf("POST %s outside the token = %d %s, want 401", tc.path, code, body)
			}

			e.Fake.Fail(tc.writes, dnsprovider.ErrUnauthorized)

			if code, body := d.acmeproxy(t, tc.path, tok, acmeproxyBody(fqdn, challenge(3))); code != http.StatusInternalServerError {
				t.Fatalf("POST %s with the Provider failing = %d %s, want 500", tc.path, code, body)
			}

			logs := d.Logs.String()

			for name, secret := range map[string]string{
				"token of the call done and of the provider failure": tok.Key,
				"token of the call refused":                          refused.Key,
				"value of the call done":                             challenge(1),
				"value of the call refused":                          challenge(2),
				"value of the provider failure":                      challenge(3),
			} {
				if strings.Contains(logs, secret) {
					t.Errorf("the logs hold the %s:\n%s", name, logs)
				}
			}

			wantAcmeproxyCallsLogged(t, logs, strings.TrimPrefix(tc.path, "/"), fqdn)
		})
	}
}

func TestEgressAgentRelaysAnAcmeproxyCallForAnAgentOnlyToken(t *testing.T) {
	for _, tc := range acmeproxyCalls {
		t.Run(tc.path, func(t *testing.T) {
			e, n := newRelayE2E(t)
			tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
			d := e.acme(t, daemonConfig{Egress: "agent", Agent: n.agent()})

			const fqdn = "_acme-challenge.example.com."

			for _, v := range tc.seed {
				d.wantPresented(t, tok, fqdn, v)
			}

			d.wantEchoed(t, tc.path, tok, fqdn, challenge(1))

			e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", txtAt60(tc.after)...)
			n.wantRelayed(t)
		})
	}
}

// wantLastAcmeproxyLog checks that the last acmeproxy call d served is
// logged with action, present or cleanup, and that the logs hold neither
// the token nor any of secrets, and returns its log line.
func (d *acmeDaemon) wantLastAcmeproxyLog(t *testing.T, action string, tok acmeToken, secrets ...string) map[string]any {
	t.Helper()

	logs := d.Logs.String()

	for _, s := range append([]string{tok.Key}, secrets...) {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("the logs hold %q:\n%s", s, logs)
		}
	}

	entries := acmeproxyLogs(t, logs)
	if len(entries) == 0 {
		t.Fatalf("no acmeproxy call logged:\n%s", logs)
	}

	got := entries[len(entries)-1]
	if got["action"] != action {
		t.Errorf("logged action = %v, want %s", got["action"], action)
	}

	return got
}

// wantLogged checks that entry holds each of want, and none of the
// fields absent.
func wantLogged(t *testing.T, entry map[string]any, want map[string]any, absent ...string) {
	t.Helper()

	for field, w := range want {
		if entry[field] != w {
			t.Errorf("logged %s = %v, want %v\nline: %v", field, entry[field], w, entry)
		}
	}

	for _, field := range absent {
		if v, ok := entry[field]; ok {
			t.Errorf("logged %s = %v, want none\nline: %v", field, v, entry)
		}
	}
}

// wantAcmeproxyForbidden sends POST path, /present or /cleanup, of a
// challenge value at fqdn with tok and checks that it answers 401
// forbidden without reaching the Provider, logged with reason and no
// Gateway error: the request was refused before any Gateway call, or after
// the token was inspected.
func (e *e2e) wantAcmeproxyForbidden(t *testing.T, d *acmeDaemon, path string, tok acmeToken, fqdn, reason string) {
	t.Helper()

	entry := e.wantAcmeproxyForbiddenLogged(t, d, path, tok, fqdn, reason)
	if err, ok := entry["error"]; ok {
		t.Errorf("logged a Gateway error %v, want none: no Gateway call was refused", err)
	}
}

// wantAcmeproxyForbiddenByGateway is wantAcmeproxyForbidden for a write
// the Gateway refused: the log line also holds the Gateway's error.
func (e *e2e) wantAcmeproxyForbiddenByGateway(t *testing.T, d *acmeDaemon, path string, tok acmeToken, fqdn, reason string) {
	t.Helper()

	entry := e.wantAcmeproxyForbiddenLogged(t, d, path, tok, fqdn, reason)
	if _, ok := entry["error"]; !ok {
		t.Errorf("logged no Gateway error, want the one the Gateway refused the call with\nline: %v", entry)
	}
}

// wantAcmeproxyForbiddenLogged is what wantAcmeproxyForbidden and
// wantAcmeproxyForbiddenByGateway share; it returns the log line.
func (e *e2e) wantAcmeproxyForbiddenLogged(
	t *testing.T, d *acmeDaemon, path string, tok acmeToken, fqdn, reason string,
) map[string]any {
	t.Helper()

	e.providerUntouched(t, func() {
		d.wantReply(t, path, tok, acmeproxyBody(fqdn, challenge(1)), http.StatusUnauthorized, replyForbidden)
	})

	entry := d.wantLastAcmeproxyLog(t, strings.TrimPrefix(path, "/"), tok, challenge(1))
	wantLogged(t, entry, map[string]any{"result": "forbidden", "level": "INFO", "fqdn": fqdn, "reason": reason})

	return entry
}

// auditEvents returns the audit events in audit with the event name.
func auditEvents(t *testing.T, audit, name string) []map[string]any {
	t.Helper()

	var out []map[string]any

	for line := range strings.Lines(audit) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("audit line %q is not JSON: %v", line, err)
		}

		if entry["event"] == name {
			out = append(out, entry)
		}
	}

	return out
}

// wantAuditedAsPatch checks that the audit event is a patch on TXT at
// _acme-challenge.example.com done by the Service Account of the ACME
// tokens.
func wantAuditedAsPatch(t *testing.T, event map[string]any) {
	t.Helper()

	for field, want := range map[string]any{
		"service_account": "acme-client", "verb": "patch", "result": "ok",
		"zone": "example.com", "record_name": "_acme-challenge", "record_type": "TXT",
	} {
		if event[field] != want {
			t.Errorf("records.patch %s = %v, want %v", field, event[field], want)
		}
	}
}

// acmeproxyLogs returns the log lines of the acmeproxy calls in logs.
func acmeproxyLogs(t *testing.T, logs string) []map[string]any {
	t.Helper()

	var out []map[string]any

	for line := range strings.Lines(logs) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}

		if entry["msg"] == "acmeproxy" {
			out = append(out, entry)
		}
	}

	return out
}

// wantAcmeproxyCallsLogged checks that logs hold three acmeproxy calls
// with action at fqdn, in _acme-challenge.example.com, each on one line
// with its own request ID: one done, one the Gateway refused for the
// Egress, and one the Provider failed.
func wantAcmeproxyCallsLogged(t *testing.T, logs, action, fqdn string) {
	t.Helper()

	entries := acmeproxyLogs(t, logs)
	if len(entries) != 3 {
		t.Fatalf("logged %d acmeproxy calls, want 3:\n%s", len(entries), logs)
	}

	ids := map[any]bool{}

	for i, want := range []struct{ result, level, reason string }{
		{"ok", "INFO", ""},
		{"forbidden", "INFO", "the Gateway refused the Permission or the Egress"},
		{"provider_error", "ERROR", "the Gateway call failed"},
	} {
		got := entries[i]
		for field, w := range map[string]any{
			"action": action, "fqdn": fqdn, "zone": "example.com", "name": "_acme-challenge",
			"result": want.result, "level": want.level,
		} {
			if got[field] != w {
				t.Errorf("%s %d logged %s = %v, want %v", action, i, field, got[field], w)
			}
		}

		if reason, _ := got["reason"].(string); reason != want.reason {
			t.Errorf("%s %d logged reason %q, want %q", action, i, reason, want.reason)
		}

		if _, hasErr := got["error"]; hasErr != (want.reason != "") {
			t.Errorf("%s %d logged error = %v, want one only when refused by the Gateway or failed", action, i, got["error"])
		}

		if _, ok := got["duration_ms"].(float64); !ok {
			t.Errorf("%s %d logged no duration_ms: %v", action, i, got)
		}

		id, _ := got["request_id"].(string)
		if !strings.HasPrefix(id, "req_") || ids[id] {
			t.Errorf("%s %d logged request_id %q, want a new req_ ID", action, i, id)
		}

		ids[id] = true
	}
}
