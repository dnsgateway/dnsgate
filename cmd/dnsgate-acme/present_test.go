package main

import (
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
