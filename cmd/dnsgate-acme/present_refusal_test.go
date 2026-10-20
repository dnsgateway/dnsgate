package main

import (
	"encoding/base64"
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

// The acmeproxy error replies the acme-dns API does not share.
const (
	replyBadRequest = `{"error":"bad_request"}`
	replyBadFQDN    = `{"error":"bad_fqdn"}`
	replyBadValue   = `{"error":"bad_value"}`
)

// wantLastPresentLog checks that the last acmeproxy call d served is
// logged as a present and that the logs hold neither the token nor any of
// secrets, and returns its log line.
func (d *acmeDaemon) wantLastPresentLog(t *testing.T, tok acmeToken, secrets ...string) map[string]any {
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
	if got["action"] != "present" {
		t.Errorf("logged action = %v, want present", got["action"])
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

// fqdn253 is a 253-character name in example.com, the longest a domain
// name may be.
var fqdn253 = strings.Repeat("a.", 121) + "example.com"

// An fqdn that is not a domain name is refused before any Gateway call,
// and never read as relative to a zone of the token. It is left out of
// the log, since it may hold anything.
func TestPresentRefusesAnFQDNThatIsNotADomainName(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge", "_acme-challenge.**"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, fqdn := range map[string]string{
		"empty":                  "",
		"only a dot":             ".",
		"single label":           "_acme-challenge",
		"single label with dot":  "_acme-challenge.",
		"empty label":            "_acme-challenge..example.com",
		"leading dot":            "._acme-challenge.example.com",
		"star":                   "_acme-challenge.*.example.com",
		"underscore inside":      "_acme-challenge.w_w.example.com",
		"only underscores":       "_acme-challenge._.example.com",
		"leading hyphen":         "_acme-challenge.-www.example.com",
		"trailing hyphen":        "_acme-challenge.www-.example.com",
		"64-character label":     "_acme-challenge." + strings.Repeat("a", 64) + ".example.com",
		"64 with underscores":    "_" + strings.Repeat("a", 63) + ".example.com",
		"254 characters":         "a" + fqdn253,
		"254 characters and dot": "a" + fqdn253 + ".",
		"space":                  "_acme-challenge.www example.com",
		"non-ASCII":              "_acme-challenge.exämple.com",
		"URL":                    "https://_acme-challenge.example.com/",
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				d.wantReply(t, "/present", tok, acmeproxyBody(fqdn, challenge(1)), http.StatusBadRequest, replyBadFQDN)
			})

			wantLogged(t, d.wantLastPresentLog(t, tok, challenge(1)),
				map[string]any{"result": "bad_fqdn", "level": "INFO"}, "fqdn", "reason", "error")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// The longest name, 253 characters, is a domain name, with or without
// the trailing dot.
func TestPresentAcceptsAnFQDNOf253Characters(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"**"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, fqdn253, challenge(1))
	d.wantPresented(t, tok, fqdn253+".", challenge(2))

	e.wantTXT(t, zoneComID, zoneCom, fqdn253, `60 "`+challenge(1)+`"`, `60 "`+challenge(2)+`"`)
}

// A value that is not a DNS-01 challenge value is refused before any
// Gateway call: the token cannot write arbitrary TXT content. The fqdn,
// valid, is logged, the value never.
func TestPresentRefusesAValueThatIsNotAChallengeValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	for name, value := range map[string]string{
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
				d.wantReply(t, "/present", tok, acmeproxyBody(fqdn, value), http.StatusBadRequest, replyBadValue)
			})

			wantLogged(t, d.wantLastPresentLog(t, tok, value),
				map[string]any{"result": "bad_value", "level": "INFO", "fqdn": fqdn}, "reason", "error")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A body that is not exactly one JSON object of the request, or that is
// over the 4 KiB cap, is refused as a bad request before any Gateway call,
// where acme-dns answers forbidden.
func TestPresentRefusesAMalformedBodyAsABadRequest(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	valid := acmeproxyBody("_acme-challenge.example.com.", challenge(1))

	for name, body := range map[string]string{
		"empty":         "",
		"not JSON":      "fqdn=_acme-challenge.example.com.",
		"truncated":     valid[:len(valid)-1],
		"array":         "[" + valid + "]",
		"number fqdn":   `{"fqdn": 1, "value": "` + challenge(1) + `"}`,
		"trailing data": valid + "{}",
		"oversized":     valid[:len(valid)-1] + `, "pad": "` + strings.Repeat("x", 5<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				d.wantReply(t, "/present", tok, body, http.StatusBadRequest, replyBadRequest)
			})

			wantLogged(t, d.wantLastPresentLog(t, tok, challenge(1)),
				map[string]any{"result": "bad_request", "level": "INFO", "reason": "malformed JSON"}, "fqdn", "error")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// wantPresentForbidden sends a /present of a challenge value at fqdn with
// tok and checks that it answers 401 forbidden without reaching the
// Provider, logged with reason and no Gateway error: the request was
// refused before any Gateway call, or after the token was inspected.
func (e *e2e) wantPresentForbidden(t *testing.T, d *acmeDaemon, tok acmeToken, fqdn, reason string) {
	t.Helper()

	entry := e.wantPresentForbiddenLogged(t, d, tok, fqdn, reason)
	if err, ok := entry["error"]; ok {
		t.Errorf("logged a Gateway error %v, want none: no Gateway call was refused", err)
	}
}

// wantPresentForbiddenByGateway is wantPresentForbidden for a write the
// Gateway refused: the log line also holds the Gateway's error.
func (e *e2e) wantPresentForbiddenByGateway(t *testing.T, d *acmeDaemon, tok acmeToken, fqdn, reason string) {
	t.Helper()

	entry := e.wantPresentForbiddenLogged(t, d, tok, fqdn, reason)
	if _, ok := entry["error"]; !ok {
		t.Errorf("logged no Gateway error, want the one the Gateway refused the call with\nline: %v", entry)
	}
}

// wantPresentForbiddenLogged is what wantPresentForbidden and
// wantPresentForbiddenByGateway share; it returns the log line.
func (e *e2e) wantPresentForbiddenLogged(t *testing.T, d *acmeDaemon, tok acmeToken, fqdn, reason string) map[string]any {
	t.Helper()

	e.providerUntouched(t, func() {
		d.wantReply(t, "/present", tok, acmeproxyBody(fqdn, challenge(1)), http.StatusUnauthorized, replyForbidden)
	})

	entry := d.wantLastPresentLog(t, tok, challenge(1))
	wantLogged(t, entry, map[string]any{"result": "forbidden", "level": "INFO", "fqdn": fqdn, "reason": reason})

	return entry
}

// A request without Basic auth, or without a password in it, is refused
// before any Gateway call.
func TestPresentRefusesARequestWithoutBasicAuth(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, cred := range map[string]acmeToken{
		"no Authorization header": {},
		"no password":             {User: tok.User},
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				e.wantPresentForbidden(t, d, cred, "_acme-challenge.example.com.", "no Basic auth")
			})
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A username other than the token's jti, another token's or none, is
// refused, and logged for the same reason as an X-Api-User other than the
// jti.
func TestPresentRefusesAUsernameOtherThanTheTokenID(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	other := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, user := range map[string]string{
		"another token's jti": other.User,
		"empty":               "",
	} {
		t.Run(name, func(t *testing.T) {
			e.wantPresentForbidden(t, d, acmeToken{Key: tok.Key, User: user}, "_acme-challenge.example.com.",
				"X-Api-User is not the token's jti")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestPresentRefusesATokenTheGatewayDoesNotAccept(t *testing.T) {
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
		"unknown": {Key: "not-a-token", User: "tok_01JACME"},
		"revoked": revoked,
		"expired": expired,
	} {
		t.Run(name, func(t *testing.T) {
			e.wantPresentForbiddenByGateway(t, d, tok, "_acme-challenge.example.com.", "the Gateway refused the token")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A token whose Permissions do not allow patch on TXT at the fqdn names no
// zone for it, so the write is refused before it reaches the Gateway.
func TestPresentRefusesAWriteTheTokensPermissionsDoNotAllow(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	onlyCreate := patchTXT("example.com", []string{"_acme-challenge"})
	onlyCreate.Verbs = []string{"create", "update"}

	onlyA := patchTXT("example.com", []string{"_acme-challenge"})
	onlyA.Types = []string{"A"}

	for name, perm := range map[string]*dnsgatev1.Permission{
		"another name": patchTXT("example.com", []string{"_acme-challenge.www"}),
		"another type": onlyA,
		"no patch":     onlyCreate,
	} {
		t.Run(name, func(t *testing.T) {
			e.wantPresentForbidden(t, d, e.token(t, perm), "_acme-challenge.example.com.",
				"the token's Permissions name no zone, or more than one, for the name")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// The Gateway refuses a write with an Egress the token's Permissions do not
// allow.
func TestPresentRefusesAWriteTheTokensEgressDoesNotAllow(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway"})
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))

	e.wantPresentForbiddenByGateway(t, d, tok, "_acme-challenge.example.com.",
		"the Gateway refused the Permission or the Egress")

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// An fqdn in no zone of the token is refused before the write: it is never
// written into another zone of the token.
func TestPresentRefusesAnFQDNInNoZoneOfTheToken(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge", "_acme-challenge.**"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	for name, fqdn := range map[string]string{
		"another zone":        "_acme-challenge.example.net.",
		"zone as a subdomain": "_acme-challenge.example.com.example.net.",
		"zone suffix":         "_acme-challenge.notexample.com.",
	} {
		t.Run(name, func(t *testing.T) {
			e.wantPresentForbidden(t, d, tok, fqdn,
				"the token's Permissions name no zone, or more than one, for the name")

			// No zone is resolved: the zone is logged, and empty.
			wantLogged(t, d.wantLastPresentLog(t, tok), map[string]any{"zone": ""})
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
	e.wantTXT(t, zoneNetID, zoneNet, "_acme-challenge.example.net")
}

// wantPresentFailed sends a /present of a challenge value at
// _acme-challenge.example.com with tok and checks that it answers 500
// provider_error, logged at error with reason and the Gateway's error.
func (d *acmeDaemon) wantPresentFailed(t *testing.T, tok acmeToken, reason string) {
	t.Helper()

	const fqdn = "_acme-challenge.example.com."

	d.wantReply(t, "/present", tok, acmeproxyBody(fqdn, challenge(1)), http.StatusInternalServerError, replyProviderError)

	entry := d.wantLastPresentLog(t, tok, challenge(1))
	wantLogged(t, entry, map[string]any{"result": "provider_error", "level": "ERROR", "fqdn": fqdn, "reason": reason})

	if _, ok := entry["error"]; !ok {
		t.Errorf("logged no error: %v", entry)
	}
}

func TestPresentAnswersProviderErrorWhenTheProviderFails(t *testing.T) {
	for name, err := range map[string]error{
		"server error": &dnsprovider.APIError{StatusCode: http.StatusBadGateway},
		// The Provider refusing the Provider Credential is not the
		// caller's fault.
		"credential refused": dnsprovider.ErrUnauthorized,
		"rate limited":       dnsprovider.ErrRateLimited,
	} {
		t.Run(name, func(t *testing.T) {
			e := newE2E(t)
			tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
			d := e.acme(t, daemonConfig{Egress: "gateway"})

			e.Fake.Fail(providertest.OpCreateRecord, err)

			d.wantPresentFailed(t, tok, "the Gateway call failed")

			e.Fake.Fail(providertest.OpCreateRecord, nil)
			e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
		})
	}
}

func TestPresentAnswersProviderErrorWhenTheGatewayIsUnreachable(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--gateway", servertest.FreePort(t)}})

	d.wantPresentFailed(t, tok, "the Gateway call failed")
}

func TestPresentAnswersProviderErrorWhenTheGatewayRefusesTheTTL(t *testing.T) {
	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: zoneComID, Name: zoneCom, State: dnsprovider.HostingActive})
	fake.SetTTLRange(120, 86400)

	e := newE2EWith(t, fake, dnsprovider.Registry{"cloudflare": fake.Factory()})
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--ttl", "60"}})

	d.wantPresentFailed(t, tok,
		"configuration error: the Gateway refused the request; check --ttl against the Provider's TTL range")

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// At the debug level each acmeproxy call also logs its request headers,
// with the Basic auth credentials, the Service Token among them, replaced
// by their length.
func TestPresentLogsTheHeadersWithoutTheTokenAtDebugLevel(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--log-level", "debug"}})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	logs := d.Logs.String()

	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(tok.User+":"+tok.Key))
	for name, secret := range map[string]string{
		"token": tok.Key, "Authorization header": auth, "value": challenge(1),
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs hold the %s:\n%s", name, logs)
		}
	}

	for _, want := range []string{`"msg":"acmeproxy headers"`, `[redacted, ` + strconv.Itoa(len(auth)) + ` bytes]`} {
		if !strings.Contains(logs, want) {
			t.Errorf("the logs lack %s:\n%s", want, logs)
		}
	}
}

func TestPresentLogsNoHeadersAtInfoLevel(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	if logs := d.Logs.String(); strings.Contains(logs, "headers") {
		t.Errorf("the headers are logged at info level:\n%s", logs)
	}
}
