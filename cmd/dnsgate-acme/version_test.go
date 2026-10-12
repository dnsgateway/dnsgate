package main

import (
	"bytes"
	"testing"
)

func TestVersionPrintsVersionAndCommit(t *testing.T) {
	version, commit = "v1.2.3", "abc1234"

	var out bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}

	if got, want := out.String(), "dnsgate-acme v1.2.3 (commit abc1234)\n"; got != want {
		t.Errorf("version output = %q, want %q", got, want)
	}
}
