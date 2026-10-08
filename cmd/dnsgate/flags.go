package main

import (
	"os"

	"github.com/spf13/pflag"
)

const (
	flagKeyDir         = "key-dir"
	flagKeyIDSuffix    = "key-id-suffix"
	envKeyDir          = "DNSGATE_KEY_DIR"
	envKeyIDSuffix     = "DNSGATE_KEY_ID_SUFFIX"
	defaultKeyDir      = "."
	defaultKeyIDSuffix = ""
)

// Flags holds the parsed CLI flags. Each falls back to an environment
// variable, then to a default.
type Flags struct {
	KeyDir      string
	KeyIDSuffix string
}

// DefaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func DefaultFlags() *Flags {
	return &Flags{
		KeyDir:      withDefaultEnv(envKeyDir, defaultKeyDir),
		KeyIDSuffix: withDefaultEnv(envKeyIDSuffix, defaultKeyIDSuffix),
	}
}

// AddKeysGenerateFlags registers the flags of "keys generate".
func (f *Flags) AddKeysGenerateFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.KeyDir, flagKeyDir, "", f.KeyDir,
		"directory to write the key files to, created with mode 0700 if missing (env "+envKeyDir+")")
	flags.StringVarP(&f.KeyIDSuffix, flagKeyIDSuffix, "", f.KeyIDSuffix,
		"<suffix> of the key IDs, see the command help (default: current UTC year-month, e.g. 2026-10; env "+envKeyIDSuffix+")")
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}
