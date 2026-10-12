package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/config"
)

func TestBootstrapSecretAllowsAtMostGroupRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-secret")
	if err := os.WriteFile(path, []byte("bootstrap-secret-0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := &config.File{BootstrapSecretFile: path}

	for _, mode := range []os.FileMode{0o600, 0o400, 0o440, 0o640} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}

		if _, err := c.BootstrapSecret(); err != nil {
			t.Errorf("BootstrapSecret with a mode %o file: %v", mode, err)
		}
	}

	for _, mode := range []os.FileMode{0o644, 0o604, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}

		if _, err := c.BootstrapSecret(); err == nil {
			t.Errorf("BootstrapSecret with a mode %o file succeeded, want an error", mode)
		}
	}
}
