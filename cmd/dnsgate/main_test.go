package main

import (
	"strings"
	"testing"
)

func TestRootCommandRunsAndManagesTheGatewayOnly(t *testing.T) {
	var got []string

	for _, c := range newRootCmd().Commands() {
		got = append(got, c.Name())
	}

	if want := "keys server version"; strings.Join(got, " ") != want {
		t.Errorf("dnsgate subcommands = %v, want %s", got, want)
	}
}

func TestRootCommandRefusesTheClientCommands(t *testing.T) {
	for _, name := range []string{"onboard", "token", "zone", "record"} {
		if _, err := runCLI(t, name, "list"); err == nil || !strings.Contains(err.Error(), "unknown command") {
			t.Errorf("dnsgate %s list: error = %v, want an unknown command", name, err)
		}
	}
}

func TestRootHelpPointsClientsToDnsgateCLI(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}

	if !strings.Contains(out, "dnsgate-cli") {
		t.Errorf("dnsgate help does not name dnsgate-cli for the client commands:\n%s", out)
	}
}

func TestServerHelpResealsTokensWithDnsgateCLI(t *testing.T) {
	out, err := runCLI(t, "server", "--help")
	if err != nil {
		t.Fatalf("server --help: %v", err)
	}

	if !strings.Contains(out, `Run "dnsgate-cli token reseal" on each token`) {
		t.Errorf("server help does not reseal tokens with dnsgate-cli:\n%s", out)
	}
}
