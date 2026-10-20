package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// The acme-dns error replies.
const (
	replyForbidden     = `{"error":"forbidden"}`
	replyBadSubdomain  = `{"error":"bad_subdomain"}`
	replyBadTXT        = `{"error":"bad_txt"}`
	replyProviderError = `{"error":"provider_error"}`
)

// wantReply sends body to path, /update with tok's credentials as acme-dns
// headers, /present or /cleanup with them as acmeproxy Basic auth, and
// checks that it answers exactly code with the JSON reply want.
func (d *acmeDaemon) wantReply(t *testing.T, path string, tok acmeToken, body string, code int, want string) {
	t.Helper()

	var gotCode int

	var got string

	if path == "/update" {
		gotCode, got = d.update(t, tok, body)
	} else {
		gotCode, got = d.acmeproxy(t, path, tok, body)
	}

	if gotCode != code || !jsonEqual(got, want) {
		t.Errorf("POST %s %s = %d %s, want %d %s\nlogs:\n%s", path, body, gotCode, got, code, want, d.Logs)
	}
}

// gatewayUntouched checks that what call does reaches neither the
// Gateway, whose audit stream it leaves as it was, nor the Provider.
func (e *e2e) gatewayUntouched(t *testing.T, call func()) {
	t.Helper()

	audit := len(e.Gateway.Audit.String())

	e.providerUntouched(t, call)

	if got := e.Gateway.Audit.String()[audit:]; got != "" {
		t.Errorf("the Gateway was called:\n%s", got)
	}
}

// providerUntouched checks that what call does never reaches the
// Provider, whether or not it reaches the Gateway.
func (e *e2e) providerUntouched(t *testing.T, call func()) {
	t.Helper()

	providerCalls := len(e.Fake.Calls())

	call()

	if got := e.Fake.Calls()[providerCalls:]; len(got) != 0 {
		t.Errorf("the Provider was called: %v", got)
	}
}

func TestUpdateRefusesASubdomainThatIsNotADNSLabelOrDomain(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, sub := range map[string]string{
		"empty":            "",
		"underscore":       "_acme",
		"empty label":      "example..com",
		"only a dot":       ".",
		"star alone":       "*.",
		"star inside":      "www.*.example.com",
		"underscore label": "www._acme.example.com",
		"255 characters":   strings.Repeat("a.", 127) + "a",
		"leading hyphen":   "-examplecom",
		"trailing hyphen":  "examplecom-",
		"64 characters":    strings.Repeat("a", 64),
		"space":            "example com",
		"non-ASCII":        "exämple",
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				d.wantReply(t, "/update", tok, updateBody(sub, challenge(1)), http.StatusBadRequest, replyBadSubdomain)
			})
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A subdomain that is neither a DNS label nor a domain name is left out of
// the log, not logged empty, since it may hold anything.
func TestUpdateLeavesASubdomainThatIsNotADNSLabelOrDomainOutOfTheLog(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, sub := range map[string]string{
		"empty":      "",
		"underscore": "_acme",
		"space":      "example com",
	} {
		t.Run(name, func(t *testing.T) {
			d.wantReply(t, "/update", tok, updateBody(sub, challenge(1)), http.StatusBadRequest, replyBadSubdomain)

			entries := updateLogs(t, d.Logs.String())
			if len(entries) == 0 {
				t.Fatalf("no update logged:\n%s", d.Logs)
			}

			wantLogged(t, entries[len(entries)-1], map[string]any{"result": "bad_subdomain", "level": "INFO"},
				"subdomain", "reason", "error")
		})
	}
}

func TestUpdateRefusesMalformedJSONAsForbidden(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	valid := updateBody("examplecom", challenge(1))

	for name, body := range map[string]string{
		"empty":            "",
		"not JSON":         "subdomain=examplecom",
		"truncated":        valid[:len(valid)-1],
		"array":            "[" + valid + "]",
		"number subdomain": `{"subdomain": 1, "txt": "` + challenge(1) + `"}`,
		"trailing data":    valid + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				d.wantReply(t, "/update", tok, body, http.StatusUnauthorized, replyForbidden)
			})
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A domain not in the Challenge Map is refused when no zone of the token
// holds its Challenge Target, and nothing is written.
func TestUpdateRefusesAnUnmappedDomainInNoZoneOfTheToken(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantReply(t, "/update", tok, updateBody("example.net", challenge(1)), http.StatusUnauthorized, replyForbidden)

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
	e.wantTXT(t, zoneNetID, zoneNet, "_acme-challenge.example.net")
}

func TestUpdateRefusesARequestWithoutAToken(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	e.gatewayUntouched(t, func() {
		d.wantReply(t, "/update", acmeToken{User: tok.User}, updateBody("examplecom", challenge(1)), http.StatusUnauthorized, replyForbidden)
	})

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestUpdateRefusesATokenTheGatewayDoesNotAccept(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway"})
	acmePerm := patchTXT("example.com", []string{"_acme-challenge"})

	revoked := e.token(t, acmePerm)
	if _, err := e.Client.RevokeToken(t.Context(), &dnsgatev1.RevokeTokenRequest{
		Token:  e.Root,
		Target: &dnsgatev1.RevokeTokenRequest_TokenId{TokenId: revoked.User},
	}); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	expired := e.tokenExpiring(t, time.Second, acmePerm)
	time.Sleep(2 * time.Second)

	for name, tok := range map[string]acmeToken{
		"garbage": {Key: "not-a-token", User: "tok_01JACME"},
		"revoked": revoked,
		"expired": expired,
	} {
		t.Run(name, func(t *testing.T) {
			d.wantReply(t, "/update", tok, updateBody("examplecom", challenge(1)), http.StatusUnauthorized, replyForbidden)
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestUpdateRefusesAWriteTheTokensPermissionsDoNotAllow(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	onlyCreate := patchTXT("example.com", []string{"_acme-challenge"})
	onlyCreate.Verbs = []string{"create", "update"}

	onlyA := patchTXT("example.com", []string{"_acme-challenge"})
	onlyA.Types = []string{"A"}

	for name, perm := range map[string]*dnsgatev1.Permission{
		"another zone": patchTXT("example.net", []string{"_acme-challenge"}),
		"another name": patchTXT("example.com", []string{"_acme-challenge.www"}),
		"another type": onlyA,
		"no patch":     onlyCreate,
		"agent egress": patchTXT("example.com", []string{"_acme-challenge"}, "agent"),
	} {
		t.Run(name, func(t *testing.T) {
			tok := e.token(t, perm)

			d.wantReply(t, "/update", tok, updateBody("examplecom", challenge(1)), http.StatusUnauthorized, replyForbidden)
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// An entry without a zone is refused, never sent to the Gateway, when the
// token's Permissions name no zone holding its name where they allow it.
func TestUpdateRefusesAnEntryWithoutAZoneTheTokenDoesNotName(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway", Map: "anycom:\n  name: _acme-challenge.example.com\n"})

	for name, perm := range map[string]*dnsgatev1.Permission{
		"another zone": patchTXT("example.net", []string{"_acme-challenge"}),
		"another name": patchTXT("example.com", []string{"_acme-challenge.www"}),
		"any zone":     patchTXT("*", []string{"_acme-challenge"}),
	} {
		t.Run(name, func(t *testing.T) {
			tok := e.token(t, perm)

			d.wantReply(t, "/update", tok, updateBody("anycom", challenge(1)), http.StatusUnauthorized, replyForbidden)
		})
	}

	if logs := d.Logs.String(); !strings.Contains(logs, "name no zone") {
		t.Errorf("the logs do not give the reason:\n%s", logs)
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestUpdateAnswersProviderErrorWhenTheProviderFails(t *testing.T) {
	for name, err := range map[string]error{
		"server error": &dnsprovider.APIError{StatusCode: http.StatusBadGateway},
		// The Provider refusing the Provider Credential is not the
		// caller's fault: the Gateway's PermissionDenied for it is still a
		// provider error.
		"credential refused": dnsprovider.ErrUnauthorized,
		"rate limited":       dnsprovider.ErrRateLimited,
	} {
		t.Run(name, func(t *testing.T) {
			e := newE2E(t)
			tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
			d := e.acme(t, daemonConfig{Egress: "gateway"})

			e.Fake.Fail(providertest.OpCreateRecord, err)

			d.wantReply(t, "/update", tok, updateBody("examplecom", challenge(1)), http.StatusInternalServerError, replyProviderError)

			e.Fake.Fail(providertest.OpCreateRecord, nil)
			e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
		})
	}
}

func TestUpdateAnswersProviderErrorWhenTheGatewayIsUnreachable(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--gateway", servertest.FreePort(t)}})

	d.wantReply(t, "/update", tok, updateBody("examplecom", challenge(1)), http.StatusInternalServerError, replyProviderError)
}

func TestUpdateAnswersProviderErrorWhenTheGatewayRefusesTheTTL(t *testing.T) {
	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: zoneComID, Name: zoneCom, State: dnsprovider.HostingActive})
	fake.SetTTLRange(120, 86400)

	e := newE2EWith(t, fake, dnsprovider.Registry{"cloudflare": fake.Factory()})
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--ttl", "60"}})

	d.wantReply(t, "/update", tok, updateBody("examplecom", challenge(1)), http.StatusInternalServerError, replyProviderError)

	if logs := d.Logs.String(); !strings.Contains(logs, "--ttl") {
		t.Errorf("the logs do not point at --ttl:\n%s", logs)
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// updateLogs returns the log lines of the /updates in logs.
func updateLogs(t *testing.T, logs string) []map[string]any {
	t.Helper()

	var out []map[string]any

	for line := range strings.Lines(logs) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}

		if entry["msg"] == "update" {
			out = append(out, entry)
		}
	}

	return out
}

func TestUpdateLogsEachRequestWithoutTheTokenOrTheTXTValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	refused := e.token(t, patchTXT("example.com", []string{"_acme-challenge.www"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantUpdated(t, tok, "examplecom", challenge(1))
	d.wantReply(t, "/update", refused, updateBody("examplecom", challenge(2)), http.StatusUnauthorized, replyForbidden)

	e.Fake.Fail(providertest.OpCreateRecord, dnsprovider.ErrUnauthorized)
	d.wantReply(t, "/update", tok, updateBody("examplecom", challenge(3)), http.StatusInternalServerError, replyProviderError)

	logs := d.Logs.String()

	for name, secret := range map[string]string{
		"token of the update added and of the provider failure": tok.Key,
		"token of the update refused":                           refused.Key,
		"TXT value of the update added":                         challenge(1),
		"TXT value of the update refused":                       challenge(2),
		"TXT value of the provider failure":                     challenge(3),
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs hold the %s:\n%s", name, logs)
		}
	}

	entries := updateLogs(t, logs)
	if len(entries) != 3 {
		t.Fatalf("logged %d updates, want 3:\n%s", len(entries), logs)
	}

	ids := map[any]bool{}

	for i, result := range []string{"ok", "forbidden", "provider_error"} {
		got := entries[i]
		for field, want := range map[string]any{
			"subdomain": "examplecom", "zone": "example.com", "name": "_acme-challenge", "result": result,
		} {
			if got[field] != want {
				t.Errorf("update %d logged %s = %v, want %v", i, field, got[field], want)
			}
		}

		if _, ok := got["duration_ms"].(float64); !ok {
			t.Errorf("update %d logged no duration_ms: %v", i, got)
		}

		id, _ := got["request_id"].(string)
		if !strings.HasPrefix(id, "req_") || ids[id] {
			t.Errorf("update %d logged request_id %q, want a new req_ ID", i, id)
		}

		ids[id] = true
	}
}

func TestUpdateRefusesATXTValueThatIsNotAChallengeValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, txt := range map[string]string{
		"empty":           "",
		"42 characters":   challenge(1)[:42],
		"44 characters":   challenge(1) + "A",
		"base64 padding":  challenge(1)[:42] + "=",
		"standard base64": challenge(1)[:41] + "+/",
		"space":           challenge(1)[:42] + " ",
		"quote":           challenge(1)[:42] + `"`,
		"SPF record":      "v=spf1 include:_spf.example.com ~all",
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				d.wantReply(t, "/update", tok, updateBody("examplecom", txt), http.StatusBadRequest, replyBadTXT)
			})
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// At the debug level each update also logs its request headers, with the
// Service Token in X-Api-Key replaced by its length.
func TestUpdateLogsTheHeadersWithoutTheTokenAtDebugLevel(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--log-level", "debug"}})

	d.wantUpdated(t, tok, "examplecom", challenge(1))

	logs := d.Logs.String()
	if strings.Contains(logs, tok.Key) {
		t.Errorf("the logs hold the token:\n%s", logs)
	}

	for _, want := range []string{`"msg":"update headers"`, tok.User, `[redacted, ` + strconv.Itoa(len(tok.Key)) + ` bytes]`} {
		if !strings.Contains(logs, want) {
			t.Errorf("the logs lack %s:\n%s", want, logs)
		}
	}
}

func TestUpdateLogsNoHeadersAtInfoLevel(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantUpdated(t, tok, "examplecom", challenge(1))

	if logs := d.Logs.String(); strings.Contains(logs, "update headers") {
		t.Errorf("the headers are logged at info level:\n%s", logs)
	}
}
