package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

func TestServerRefusesToStartWithBadConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(t *testing.T, env *servertest.Env)
		want string
	}{
		"missing config file": {
			edit: func(t *testing.T, env *servertest.Env) { env.Config = filepath.Join(env.Dir, "missing.yaml") },
			want: "reading config",
		},
		"unknown field": {
			edit: func(t *testing.T, env *servertest.Env) {
				servertest.WriteFile(t, env.Config, "listen: 127.0.0.1:0\nbootstrapSecret: inline\n", 0o600)
			},
			want: "bootstrapSecret",
		},
		"missing setting": {
			edit: func(t *testing.T, env *servertest.Env) {
				servertest.WriteFile(t, env.Config, "listen: 127.0.0.1:0\n", 0o600)
			},
			want: "is required",
		},
		"missing key file": {
			edit: func(t *testing.T, env *servertest.Env) {
				if err := os.Remove(filepath.Join(env.Dir, "keys", "enc-e2e.pem")); err != nil {
					t.Fatal(err)
				}
			},
			want: "enc-e2e.pem",
		},
		"loose bootstrap secret file": {
			edit: func(t *testing.T, env *servertest.Env) {
				if err := os.Chmod(filepath.Join(env.Dir, "bootstrap-secret"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "bootstrap secret file",
		},
		"decryption key without retireAt": {
			edit: func(t *testing.T, env *servertest.Env) {
				env.WriteDecryptionKeysConfig(t, "    - keyFile: keys/enc-old.pem\n")
			},
			want: "keys.decryptionKeys[0].retireAt is required",
		},
		"decryption key without keyFile": {
			edit: func(t *testing.T, env *servertest.Env) {
				env.WriteDecryptionKeysConfig(t, "    - retireAt: 2030-01-01T00:00:00Z\n")
			},
			want: "keys.decryptionKeys[0].keyFile is required",
		},
		"decryption key with a malformed retireAt": {
			edit: func(t *testing.T, env *servertest.Env) {
				env.WriteDecryptionKeysConfig(t, "    - keyFile: keys/enc-old.pem\n      retireAt: next month\n")
			},
			want: "parsing config",
		},
		"decryption key with an unknown field": {
			edit: func(t *testing.T, env *servertest.Env) {
				env.WriteDecryptionKeysConfig(t, "    - keyFile: keys/enc-old.pem\n      retireAt: 2030-01-01T00:00:00Z\n      retireAfter: 720h\n")
			},
			want: "retireAfter",
		},
		"decryption key that is the current key": {
			edit: func(t *testing.T, env *servertest.Env) {
				env.WriteDecryptionKeysConfig(t, "    - keyFile: keys/enc-e2e.pem\n      retireAt: 2030-01-01T00:00:00Z\n")
			},
			want: "used twice",
		},
		"missing decryption key file": {
			edit: func(t *testing.T, env *servertest.Env) {
				env.WriteDecryptionKeysConfig(t, "    - keyFile: keys/enc-old.pem\n      retireAt: 2030-01-01T00:00:00Z\n")
			},
			want: "enc-old.pem",
		},
		"negative maxAncestors": {
			edit: func(t *testing.T, env *servertest.Env) {
				config, err := os.ReadFile(env.Config)
				if err != nil {
					t.Fatal(err)
				}

				servertest.WriteFile(t, env.Config, string(config)+"tokens:\n  maxAncestors: -1\n", 0o600)
			},
			want: "tokens.maxAncestors",
		},
		"missing database file setting": {
			edit: func(t *testing.T, env *servertest.Env) {
				config, err := os.ReadFile(env.Config)
				if err != nil {
					t.Fatal(err)
				}

				servertest.WriteFile(t, env.Config, strings.Replace(string(config), "database:\n  sqliteFile: dnsgate.db\n", "", 1), 0o600)
			},
			want: "database.sqliteFile is required",
		},
		"database file in a missing directory": {
			edit: func(t *testing.T, env *servertest.Env) {
				config, err := os.ReadFile(env.Config)
				if err != nil {
					t.Fatal(err)
				}

				servertest.WriteFile(t, env.Config, strings.Replace(string(config), "sqliteFile: dnsgate.db", "sqliteFile: missing/dnsgate.db", 1), 0o600)
			},
			want: "revocation database",
		},
		"short bootstrap secret": {
			edit: func(t *testing.T, env *servertest.Env) {
				servertest.WriteFile(t, filepath.Join(env.Dir, "bootstrap-secret"), "short\n", 0o600)
			},
			want: "fewer than 16 bytes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := servertest.NewEnv(t)
			tc.edit(t, env)

			out, err := runCLI(t, "server", "--config", env.Config)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("server error = %v, want one containing %q\n%s", err, tc.want, out)
			}
		})
	}
}

func TestServerTakesConfigFromEnv(t *testing.T) {
	env := servertest.NewEnv(t)
	t.Setenv("DNSGATE_CONFIG", filepath.Join(env.Dir, "missing.yaml"))

	if _, err := runCLI(t, "server"); err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Errorf("server error = %v, want one naming the config file from DNSGATE_CONFIG", err)
	}
}
