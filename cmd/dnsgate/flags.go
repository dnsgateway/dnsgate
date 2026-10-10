package main

import (
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

const (
	flagKeyDir      = "key-dir"
	flagKeyIDSuffix = "key-id-suffix"
	flagConfig      = "config"
	flagLogLevel    = "log-level"

	envKeyDir      = "DNSGATE_KEY_DIR"
	envKeyIDSuffix = "DNSGATE_KEY_ID_SUFFIX"
	envConfig      = "DNSGATE_CONFIG"
	envLogLevel    = "DNSGATE_LOG_LEVEL"
)

const (
	defaultKeyDir      = "keys"
	defaultKeyIDSuffix = ""
	defaultConfig      = "dnsgate.yaml"
	defaultLogLevel    = "info"
)

// Flags holds the parsed CLI flags. Each falls back to an environment
// variable, then to a default.
type Flags struct {
	KeyDir      string
	KeyIDSuffix string

	Config   string
	LogLevel string
}

// DefaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func DefaultFlags() *Flags {
	return &Flags{
		KeyDir:      withDefaultEnv(envKeyDir, defaultKeyDir),
		KeyIDSuffix: withDefaultEnv(envKeyIDSuffix, defaultKeyIDSuffix),
		Config:      withDefaultEnv(envConfig, defaultConfig),
		LogLevel:    withDefaultEnv(envLogLevel, defaultLogLevel),
	}
}

// AddKeysGenerateFlags registers the flags of "keys generate".
func (f *Flags) AddKeysGenerateFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.KeyDir, flagKeyDir, "", f.KeyDir,
		"directory to write the key files to, created with mode 0700 if missing (env "+envKeyDir+")")
	flags.StringVarP(&f.KeyIDSuffix, flagKeyIDSuffix, "", f.KeyIDSuffix,
		"<suffix> of the key IDs, see the command help (default: current UTC year-month, e.g. 2026-10; env "+envKeyIDSuffix+")")
}

// AddServerFlags registers the flags of "server".
func (f *Flags) AddServerFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Config, flagConfig, "", f.Config,
		"Gateway configuration file (env "+envConfig+")")
	flags.StringVarP(&f.LogLevel, flagLogLevel, "", f.LogLevel,
		"lowest level of the logs written: "+logLevelNames()+" (env "+envLogLevel+")")
}

// logLevels are the accepted --log-level values and their slog levels,
// most severe first.
var logLevels = []struct {
	name  string
	level slog.Level
}{
	{"error", slog.LevelError},
	{"warn", slog.LevelWarn},
	{"info", slog.LevelInfo},
	{"debug", slog.LevelDebug},
}

// logLevelNames returns the accepted --log-level values, most severe first.
func logLevelNames() string {
	names := make([]string, len(logLevels))
	for i, l := range logLevels {
		names[i] = l.name
	}

	return strings.Join(names, ", ")
}

// checkServerFlags checks the flags of "server" and returns the log level
// asked for.
func checkServerFlags(f *Flags) (slog.Level, error) {
	for _, l := range logLevels {
		if l.name == f.LogLevel {
			return l.level, nil
		}
	}

	return 0, errors.New(`unknown log level "` + f.LogLevel + `": use ` + logLevelNames())
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}
