package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/keys"
)

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)

	err := cmd.Execute()

	return out.String(), err
}

func TestKeysGenerateWritesLoadableKeyPairs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")

	out, err := runCLI(t, "keys", "generate", "--dir", dir, "--kid-suffix", "2026-10")
	if err != nil {
		t.Fatalf("keys generate: %v\n%s", err, out)
	}

	for _, want := range []string{"sig-2026-10", "enc-2026-10", filepath.Join(dir, "sig-2026-10.pem"), filepath.Join(dir, "enc-2026-10.pub.pem")} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}

	src, err := keys.LoadFiles(filepath.Join(dir, "sig-2026-10.pem"), filepath.Join(dir, "enc-2026-10.pem"))
	if err != nil {
		t.Fatal(err)
	}

	if kid, _ := src.EncryptionKey(); kid != "enc-2026-10" || src.SigningKeyID() != "sig-2026-10" {
		t.Errorf("loaded kids = %q, %q", src.SigningKeyID(), kid)
	}

	if _, err := runCLI(t, "keys", "generate", "--dir", dir, "--kid-suffix", "2026-10"); err == nil {
		t.Error("generating the same kids again succeeded, want an error")
	}
}

func TestKeysGenerateTakesDirFromEnvAndDefaultsSuffixToTheMonth(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	t.Setenv("DNSGATE_KEY_DIR", dir)

	month := time.Now().UTC().Format("2006-01")

	if out, err := runCLI(t, "keys", "generate"); err != nil {
		t.Fatalf("keys generate: %v\n%s", err, out)
	}

	for _, name := range []string{"sig-" + month + ".pem", "enc-" + month + ".pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
}
