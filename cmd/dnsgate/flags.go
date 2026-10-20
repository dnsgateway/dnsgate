package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/loglevel"
	"github.com/dnsgateway/dnsgate/internal/server"
)

const (
	flagKeyDir      = "key-dir"
	flagKeyIDSuffix = "key-id-suffix"
	flagConfig      = "config"
	flagListen      = "listen"
	flagTLSCertFile = "tls-cert-file"
	flagTLSKeyFile  = "tls-key-file"
	flagLogLevel    = "log-level"

	envKeyDir      = "DNSGATE_KEY_DIR"
	envKeyIDSuffix = "DNSGATE_KEY_ID_SUFFIX"
	envConfig      = "DNSGATE_CONFIG"
	envListen      = "DNSGATE_LISTEN_ADDRESS"
	envTLSCertFile = "DNSGATE_TLS_CERT_FILE"
	envTLSKeyFile  = "DNSGATE_TLS_KEY_FILE"
	envLogLevel    = "DNSGATE_LOG_LEVEL"
)

const (
	defaultKeyDir      = "keys"
	defaultKeyIDSuffix = ""
	defaultConfig      = "dnsgate.yaml"
	defaultListen      = server.DefaultListen
	defaultTLSCertFile = "tls.crt"
	defaultTLSKeyFile  = "tls.key"
	defaultLogLevel    = "info"
)

// Flags holds the parsed CLI flags. Each falls back to an environment
// variable, then to a default.
type Flags struct {
	KeyDir      string
	KeyIDSuffix string

	Config      string
	Listen      string
	TLSCertFile string
	TLSKeyFile  string
	LogLevel    string
}

// DefaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func DefaultFlags() *Flags {
	return &Flags{
		KeyDir:      withDefaultEnv(envKeyDir, defaultKeyDir),
		KeyIDSuffix: withDefaultEnv(envKeyIDSuffix, defaultKeyIDSuffix),
		Config:      withDefaultEnv(envConfig, defaultConfig),
		Listen:      withDefaultEnv(envListen, defaultListen),
		TLSCertFile: withDefaultEnv(envTLSCertFile, defaultTLSCertFile),
		TLSKeyFile:  withDefaultEnv(envTLSKeyFile, defaultTLSKeyFile),
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
	flags.StringVarP(&f.Listen, flagListen, "", f.Listen,
		"TCP address the gRPC API is served on (env "+envListen+")")
	flags.StringVarP(&f.TLSCertFile, flagTLSCertFile, "", f.TLSCertFile,
		"PEM file of the server certificate, with any intermediates after it (env "+envTLSCertFile+")")
	flags.StringVarP(&f.TLSKeyFile, flagTLSKeyFile, "", f.TLSKeyFile,
		"PEM file of the server certificate's private key (env "+envTLSKeyFile+")")
	flags.StringVarP(&f.LogLevel, flagLogLevel, "", f.LogLevel,
		"lowest level of the logs written: "+loglevel.Names()+" (env "+envLogLevel+")")
}

// checkServerFlags checks the flags of "server" and returns the log level
// asked for.
func checkServerFlags(f *Flags) (slog.Level, error) {
	var level slog.Level

	if err := loglevel.NewValue(&level).Set(f.LogLevel); err != nil {
		return 0, fmt.Errorf("--%s or %s %q: %w", flagLogLevel, envLogLevel, f.LogLevel, err)
	}

	return level, nil
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}
