package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestUpdateAddsTheChallengeValueThroughTheGateway(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantUpdated(t, tok, "examplecom", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestUpdateRepeatedKeepsOneCopyOfTheValue(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantUpdated(t, tok, "examplecom", challenge(1))
	d.wantUpdated(t, tok, "examplecom", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestUpdateAddsASecondValueNextToTheFirst(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantUpdated(t, tok, "examplecom", challenge(1))
	d.wantUpdated(t, tok, "examplecom", challenge(2))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com",
		`60 "`+challenge(1)+`"`, `60 "`+challenge(2)+`"`)
}

// A CNAME-delegated Challenge Target is just another name: the daemon
// writes where the map points, in another zone, and never looks up DNS
// (no CNAME exists anywhere here).
func TestUpdateWritesACNAMEDelegatedTargetInAnotherZone(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.net", []string{"challenge-123.acme"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	d.wantUpdated(t, tok, "delegated", challenge(3))

	e.wantTXT(t, zoneNetID, zoneNet, "challenge-123.acme.example.net", `60 "`+challenge(3)+`"`)
	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// An entry without a zone names its target by absolute name; the zone
// comes from the token's Permissions, so one entry serves any zone.
func TestUpdateTakesTheZoneOfAnEntryWithoutOneFromTheToken(t *testing.T) {
	e := newE2E(t)
	d := e.acme(t, daemonConfig{Egress: "gateway", Map: `
anycom:
  name: _acme-challenge.example.com.
anynet:
  name: Challenge-123.ACME.example.net
`})

	d.wantUpdated(t, e.token(t, patchTXT("example.com", []string{"_acme-challenge"})), "anycom", challenge(1))
	d.wantUpdated(t, e.token(t,
		patchTXT("example.com", []string{"_acme-challenge"}),
		patchTXT("example.net", []string{"challenge-123.acme"}),
	), "anynet", challenge(2))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
	e.wantTXT(t, zoneNetID, zoneNet, "challenge-123.acme.example.net", `60 "`+challenge(2)+`"`)
}

func TestUpdateWritesWithTheConfiguredTTL(t *testing.T) {
	t.Run("flag", func(t *testing.T) {
		e := newE2E(t)
		tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
		d := e.acme(t, daemonConfig{Egress: "gateway", Args: []string{"--ttl", "120"}})

		d.wantUpdated(t, tok, "examplecom", challenge(1))

		e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `120 "`+challenge(1)+`"`)
	})

	t.Run("env", func(t *testing.T) {
		t.Setenv("DNSGATE_ACME_TTL", "300")

		e := newE2E(t)
		tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
		d := e.acme(t, daemonConfig{Egress: "gateway"})

		d.wantUpdated(t, tok, "examplecom", challenge(1))

		e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `300 "`+challenge(1)+`"`)
	})
}

func TestUpdateReadsAJSONChallengeMap(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge.www"}))
	d := e.acme(t, daemonConfig{
		Egress:  "gateway",
		MapFile: "map.json",
		Map:     `{"www": {"zone": "example.com", "name": "_acme-challenge.www"}}`,
	})

	d.wantUpdated(t, tok, "www", challenge(4))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.www.example.com", `60 "`+challenge(4)+`"`)
}

func TestUpdateOverHTTPS(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway", TLS: true})

	d.wantUpdated(t, tok, "examplecom", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
}

func TestUpdateRefusesAnXAPIUserOtherThanTheTokenID(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	other := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	code, body := d.update(t, acmeToken{Key: tok.Key, User: other.User}, updateBody("examplecom", challenge(1)))
	if code != http.StatusUnauthorized || !jsonEqual(body, `{"error":"forbidden"}`) {
		t.Errorf("POST /update = %d %s, want 401 forbidden", code, body)
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

// A body past the 4 KiB cap is refused as malformed, and nothing is
// written.
func TestUpdateRefusesAnOversizedBody(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	body := `{"subdomain": "examplecom", "txt": "` + challenge(1) + `", "pad": "` + strings.Repeat("x", 5<<10) + `"}`

	code, got := d.update(t, tok, body)
	if code != http.StatusUnauthorized || !jsonEqual(got, `{"error":"forbidden"}`) {
		t.Errorf("POST /update with a %d-byte body = %d %s, want 401 forbidden", len(body), code, got)
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}
