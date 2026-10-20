package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

// A cleanup removes only its value: another validation still running at
// the same Challenge Target keeps its own.
func TestCleanupRemovesOnlyItsValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))
	d.wantPresented(t, tok, fqdn, challenge(2))

	d.wantCleanedUp(t, tok, fqdn, challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(2)+`"`)
}

// A cleanup of a value that is not there succeeds and changes nothing, so
// retries and double cleanups are harmless.
func TestCleanupOfAValueThatIsNotThereSucceeds(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))

	d.wantCleanedUp(t, tok, fqdn, challenge(2))
	d.wantCleanedUp(t, tok, fqdn, challenge(1))
	d.wantCleanedUp(t, tok, fqdn, challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A cleanup at a Challenge Target that holds no TXT RRset at all succeeds
// without a write: the Gateway's patch treats it as no change.
func TestCleanupWhereTheRRsetDoesNotExistSucceeds(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	e.providerNotWritten(t, func() {
		d.wantCleanedUp(t, tok, "_acme-challenge.example.com.", challenge(1))
	})

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// zoneRecords returns every record the fake Provider holds in the zone
// with zoneID, each as "type name TTL value", sorted.
func (e *e2e) zoneRecords(t *testing.T, zoneID, zone string) []string {
	t.Helper()

	set, err := e.Fake.ListRecords(t.Context(), dnsprovider.Zone{ID: zoneID, Name: zone}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]string, 0, len(set.Records))
	for _, r := range set.Records {
		out = append(out, fmt.Sprintf("%s %s %d %s", r.Type, r.Name, r.TTL, r.Value))
	}

	slices.Sort(out)

	return out
}

// A present then a cleanup of the same value leaves the zone as it was,
// a value already at the Challenge Target, with its own TTL, included.
func TestPresentThenCleanupLeavesTheZoneAsItWas(t *testing.T) {
	e := newE2E(t)
	e.Fake.SetRecords(zoneComID,
		dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300},
		dnsprovider.Record{ID: "r2", Type: "TXT", Name: "_acme-challenge.example.com", Value: `"` + challenge(2) + `"`, TTL: 300},
		dnsprovider.Record{ID: "r3", Type: "TXT", Name: "example.com", Value: `"v=spf1 -all"`, TTL: 3600},
	)

	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge", "_acme-challenge.**"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	before := e.zoneRecords(t, zoneComID, zoneCom)
	if len(before) != 3 {
		t.Fatalf("zone before = %q, want the 3 records set", before)
	}

	for _, fqdn := range []string{"_acme-challenge.example.com.", "_acme-challenge.www.example.com."} {
		d.wantPresented(t, tok, fqdn, challenge(1))
		d.wantCleanedUp(t, tok, fqdn, challenge(1))
	}

	if after := e.zoneRecords(t, zoneComID, zoneCom); !slices.Equal(after, before) {
		t.Errorf("zone after present and cleanup = %q, want as before %q", after, before)
	}
}

// A cleanup without Basic auth, or without a password in it, is refused
// before any Gateway call, and the value stays.
func TestCleanupRefusesARequestWithoutBasicAuth(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))

	for name, cred := range map[string]acmeToken{
		"no Authorization header": {},
		"no password":             {User: tok.User},
	} {
		t.Run(name, func(t *testing.T) {
			e.gatewayUntouched(t, func() {
				entry := e.wantAcmeproxyForbiddenLogged(t, d, "/cleanup", cred, fqdn, "no Basic auth")
				wantLogged(t, entry, map[string]any{"name": fqdn}, "error")
			})
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

// A cleanup whose username is not the token's jti is refused for the same
// reason as a present, and the value stays.
func TestCleanupRefusesAUsernameOtherThanTheTokenID(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	other := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))

	for name, user := range map[string]string{
		"another token's jti": other.User,
		"empty":               "",
	} {
		t.Run(name, func(t *testing.T) {
			e.wantAcmeproxyForbidden(t, d, "/cleanup", acmeToken{Key: tok.Key, User: user}, fqdn,
				"X-Api-User is not the token's jti")
		})
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestCleanupIsAuditedAsAPatchByTheTokensServiceAccount(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantPresented(t, tok, "_acme-challenge.example.com.", challenge(1))

	audited := len(e.Gateway.Audit.String())

	d.wantCleanedUp(t, tok, "_acme-challenge.example.com.", challenge(1))

	events := auditEvents(t, e.Gateway.Audit.String()[audited:], "records.patch")
	if len(events) != 1 {
		t.Fatalf("the cleanup audited %d records.patch events, want 1:\n%s", len(events), e.Gateway.Audit)
	}

	wantAuditedAsPatch(t, events[0])
}

func TestCleanupLogsEachRequestWithoutTheTokenOrTheValue(t *testing.T) {
	e := newE2E(t)
	e.Fake.SetRecords(zoneComID,
		dnsprovider.Record{ID: "r1", Type: "TXT", Name: "_acme-challenge.example.com", Value: `"` + challenge(1) + `"`, TTL: 60},
		dnsprovider.Record{ID: "r3", Type: "TXT", Name: "_acme-challenge.example.com", Value: `"` + challenge(3) + `"`, TTL: 60},
	)

	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	refused := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	const fqdn = "_acme-challenge.example.com."

	d.wantCleanedUp(t, tok, fqdn, challenge(1))

	if code, body := d.acmeproxy(t, "/cleanup", refused, acmeproxyBody(fqdn, challenge(2))); code != http.StatusUnauthorized {
		t.Fatalf("POST /cleanup outside the token = %d %s, want 401", code, body)
	}

	e.Fake.Fail(providertest.OpDeleteRecord, dnsprovider.ErrUnauthorized)

	if code, body := d.acmeproxy(t, "/cleanup", tok, acmeproxyBody(fqdn, challenge(3))); code != http.StatusInternalServerError {
		t.Fatalf("POST /cleanup with the Provider failing = %d %s, want 500", code, body)
	}

	logs := d.Logs.String()

	for name, secret := range map[string]string{
		"token of the cleanup done and of the provider failure": tok.Key,
		"token of the cleanup refused":                          refused.Key,
		"value of the cleanup done":                             challenge(1),
		"value of the cleanup refused":                          challenge(2),
		"value of the provider failure":                         challenge(3),
	} {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs hold the %s:\n%s", name, logs)
		}
	}

	wantAcmeproxyCallsLogged(t, logs, "cleanup", fqdn)
}

func TestEgressAgentRelaysACleanupForAnAgentOnlyToken(t *testing.T) {
	e, n := newRelayE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Egress: "agent", Agent: n.agent()})

	const fqdn = "_acme-challenge.example.com."

	d.wantPresented(t, tok, fqdn, challenge(1))
	d.wantPresented(t, tok, fqdn, challenge(2))
	d.wantCleanedUp(t, tok, fqdn, challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(2)+`"`)
	n.wantRelayed(t)
}
