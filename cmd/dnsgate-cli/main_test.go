package main

import (
	"strings"
	"testing"
)

func TestRootCommandCallsTheGatewayOnly(t *testing.T) {
	var got []string

	for _, c := range newRootCmd().Commands() {
		got = append(got, c.Name())
	}

	if want := "onboard record token version zone"; strings.Join(got, " ") != want {
		t.Errorf("dnsgate-cli subcommands = %v, want %s", got, want)
	}
}

func TestRootCommandRefusesTheGatewayCommands(t *testing.T) {
	for _, name := range []string{"server", "keys"} {
		if _, err := runCLI(t, name); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("dnsgate-cli %s: error = %v, want an unknown command", name, err)
		}
	}
}

func TestRootHelpSaysItManagesRecordsThroughTheGateway(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}

	if !strings.Contains(out, "dnsgate-cli manages DNS records at a Provider through the Gateway.") {
		t.Errorf("dnsgate-cli help does not describe it:\n%s", out)
	}
}
