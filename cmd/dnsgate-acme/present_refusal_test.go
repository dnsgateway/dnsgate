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

			wantLogged(t, d.wantLastAcmeproxyLog(t, "present", tok, challenge(1)),
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

			wantLogged(t, d.wantLastAcmeproxyLog(t, "present", tok, value),
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

			wantLogged(t, d.wantLastAcmeproxyLog(t, "present", tok, challenge(1)),
				map[string]any{"result": "bad_request", "level": "INFO", "reason": "malformed JSON"}, "fqdn", "error")
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
			e.wantAcmeproxyForbiddenByGateway(t, d, "/present", tok, "_acme-challenge.example.com.", "the Gateway refused the token")
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
			e.wantAcmeproxyForbidden(t, d, "/present", e.token(t, perm), "_acme-challenge.example.com.",
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

	e.wantAcmeproxyForbiddenByGateway(t, d, "/present", tok, "_acme-challenge.example.com.",
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
			e.wantAcmeproxyForbidden(t, d, "/present", tok, fqdn,
				"the token's Permissions name no zone, or more than one, for the name")

			// No zone is resolved: the zone is logged, and empty.
			wantLogged(t, d.wantLastAcmeproxyLog(t, "present", tok), map[string]any{"zone": ""})
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

	entry := d.wantLastAcmeproxyLog(t, "present", tok, challenge(1))
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
