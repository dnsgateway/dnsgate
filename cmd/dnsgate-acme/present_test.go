package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

func TestPresentAddsTheChallengeValueThroughTheGateway(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestPresentRepeatedKeepsOneCopyOfTheValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))
	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestPresentAddsASecondValueNextToTheFirst(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))
	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(2))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com",
		`60 "`+challenge(1)+`"`, `60 "`+challenge(2)+`"`)
}

func TestPresentWritesWithTheConfiguredTTL(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--ttl", "120"}})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `120 "`+challenge(1)+`"`)
}

func TestPresentIgnoresTheTrailingDotAndCaseOfTheFQDN(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge.www", "_acme-challenge.api"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.www.example.com", challenge(1))
	d.wantPresented(t, tok, "_ACME-Challenge.API.Example.COM.", challenge(2))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.www.example.com", `60 "`+challenge(1)+`"`)
	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.api.example.com", `60 "`+challenge(2)+`"`)
}

// A CNAME-following client sends the delegated Challenge Target: the
// daemon writes it in its own zone, without the Challenge Map and without
// looking up DNS.
func TestPresentWritesACNAMEDelegatedTargetInAnotherZone(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t,
		patchTXT("example.com", []string{"_acme-challenge"}),
		patchTXT("example.net", []string{"challenge-123.acme"}),
	)
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "challenge-123.acme.example.net.", challenge(3))

	e.wantTXT(t, zoneNetID, zoneNet, "challenge-123.acme.example.net", `60 "`+challenge(3)+`"`)
	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestPresentWritesInTheLongestZoneOfTheToken(t *testing.T) {
	const zoneSub, zoneSubID = "acme.example.com", "z-sub"

	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: zoneComID, Name: zoneCom, State: dnsprovider.HostingActive}).
		AddZone(dnsprovider.Zone{ID: zoneSubID, Name: zoneSub, State: dnsprovider.HostingActive})

	e := newE2EWith(t, fake, dnsprovider.Registry{"cloudflare": fake.Factory()})
	tok := e.token(t,
		patchTXT("example.com", []string{"_acme-challenge.**"}),
		patchTXT("acme.example.com", []string{"_acme-challenge.www"}),
	)
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.www.acme.example.com.", challenge(1))

	e.wantTXT(t, zoneSubID, zoneSub, "_acme-challenge.www.acme.example.com", `60 "`+challenge(1)+`"`)
	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.www.acme.example.com")
}

func TestPresentOverHTTPS(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", TLS: true})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestEgressAgentRelaysAPresentForAnAgentOnlyToken(t *testing.T) {
	e, n := newRelayE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Egress: "agent", Agent: n.agent()})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
	n.wantRelayed(t)
}

// wantPresentRefused checks that a /present of a challenge value at
// _acme-challenge.example.com with tok answers 401 forbidden and writes
// nothing.
func (e *e2e) wantPresentRefused(t *testing.T, d *acmeDaemon, tok acmeToken) {
	t.Helper()

	providerCalls := len(e.Fake.Calls())

	code, body := d.present(t, tok, acmeproxyBody("_acme-challenge.example.com.", challenge(1)))
	if code != http.StatusUnauthorized || !jsonEqual(body, replyForbidden) {
		t.Errorf("POST /present = %d %s, want 401 forbidden\nlogs:\n%s", code, body, d.Logs)
	}

	if got := e.Fake.Calls()[providerCalls:]; len(got) != 0 {
		t.Errorf("the Provider was called: %v", got)
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestPresentRefusesARequestWithoutBasicAuth(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	e.gatewayUntouched(t, func() {
		code, body := d.present(t, acmeToken{}, acmeproxyBody("_acme-challenge.example.com.", challenge(1)))
		if code != http.StatusUnauthorized || !jsonEqual(body, replyForbidden) {
			t.Errorf("POST /present = %d %s, want 401 forbidden", code, body)
		}
	})

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")

	logs := d.Logs.String()
	if !strings.Contains(logs, `"reason":"no Basic auth"`) {
		t.Errorf("the logs do not give the reason:\n%s", logs)
	}

	if !strings.Contains(logs, `"name":"_acme-challenge.example.com."`) {
		t.Errorf("the logs do not give the name:\n%s", logs)
	}
}

func TestPresentRefusesAUsernameOtherThanTheTokenID(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	other := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	e.wantPresentRefused(t, d, acmeToken{Key: tok.Key, User: other.User})
	e.wantPresentRefused(t, d, acmeToken{Key: tok.Key, User: ""})
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

func TestPresentIsAuditedAsAPatchByTheTokensServiceAccount(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	events := auditEvents(t, e.Gateway.Audit.String(), "records.patch")
	if len(events) != 1 {
		t.Fatalf("audited %d records.patch events, want 1:\n%s", len(events), e.Gateway.Audit)
	}

	for field, want := range map[string]any{
		"service_account": "acme-client", "verb": "patch", "result": "ok",
		"zone": "example.com", "record_name": "_acme-challenge", "record_type": "TXT",
	} {
		if events[0][field] != want {
			t.Errorf("records.patch %s = %v, want %v", field, events[0][field], want)
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

func TestPresentLogsEachRequestWithoutTheTokenOrTheValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	refused := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))

	if code, body := d.present(t, refused, acmeproxyBody(fqdn, challenge(2))); code != http.StatusUnauthorized {
		t.Fatalf("POST /present outside the token = %d %s, want 401", code, body)
	}

	e.Fake.Fail(providertest.OpCreateRecord, dnsprovider.ErrUnauthorized)

	if code, body := d.present(t, tok, acmeproxyBody(fqdn, challenge(3))); code != http.StatusInternalServerError {
		t.Fatalf("POST /present with the Provider failing = %d %s, want 500", code, body)
	}

	logs := d.Logs.String()

	for name, secret := range map[string]string{
		"token of the present added and of the provider failure": tok.Key,
		"token of the present refused":                           refused.Key,
		"value of the present added":                             challenge(1),
		"value of the present refused":                           challenge(2),
		"value of the provider failure":                          challenge(3),
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs hold the %s:\n%s", name, logs)
		}
	}

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
			"action": "present", "fqdn": fqdn, "zone": "example.com", "name": "_acme-challenge",
			"result": want.result, "level": want.level,
		} {
			if got[field] != w {
				t.Errorf("present %d logged %s = %v, want %v", i, field, got[field], w)
			}
		}

		if reason, _ := got["reason"].(string); reason != want.reason {
			t.Errorf("present %d logged reason %q, want %q", i, reason, want.reason)
		}

		if _, hasErr := got["error"]; hasErr != (want.reason != "") {
			t.Errorf("present %d logged error = %v, want one only when refused by the Gateway or failed", i, got["error"])
		}

		if _, ok := got["duration_ms"].(float64); !ok {
			t.Errorf("present %d logged no duration_ms: %v", i, got)
		}

		id, _ := got["request_id"].(string)
		if !strings.HasPrefix(id, "req_") || ids[id] {
			t.Errorf("present %d logged request_id %q, want a new req_ ID", i, id)
		}

		ids[id] = true
	}
}
