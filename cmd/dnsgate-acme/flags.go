package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/acme"
	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
)

const (
	flagListen       = "listen"
	flagTLSCertFile  = "tls-cert-file"
	flagTLSKeyFile   = "tls-key-file"
	flagChallengeMap = "challenge-map"
	flagTTL          = "ttl"
	flagLogLevel     = "log-level"
	flagGateway      = gatewayconn.FlagGateway
	flagCAFile       = gatewayconn.FlagCAFile
	flagEgress       = gatewayconn.FlagEgress

	envListen       = "DNSGATE_ACME_LISTEN_ADDRESS"
	envTLSCertFile  = "DNSGATE_ACME_TLS_CERT_FILE"
	envTLSKeyFile   = "DNSGATE_ACME_TLS_KEY_FILE"
	envChallengeMap = "DNSGATE_ACME_CHALLENGE_MAP"
	envTTL          = "DNSGATE_ACME_TTL"
	envLogLevel     = "DNSGATE_ACME_LOG_LEVEL"
	envGateway      = gatewayconn.EnvGateway
	envCAFile       = gatewayconn.EnvCAFile
	envEgress       = gatewayconn.EnvEgress
)

const (
	defaultListen   = acme.DefaultListen
	defaultTTL      = 60
	defaultLogLevel = "info"
	defaultGateway  = gatewayconn.DefaultGateway
)

// Flags holds the parsed CLI flags. Each falls back to an environment
// variable, then to a default.
type Flags struct {
	Listen       string
	TLSCertFile  string
	TLSKeyFile   string
	ChallengeMap string
	TTL          uint32
	LogLevel     string

	Gateway string
	CAFiles []string
	Egress  string

	// envTTLErr is why the TTL in the environment was not taken, if it was
	// not; it stops the daemon unless --ttl replaces it.
	envTTLErr error
}

// DefaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func DefaultFlags() *Flags {
	f := &Flags{
		Listen:       withDefaultEnv(envListen, defaultListen),
		TLSCertFile:  withDefaultEnv(envTLSCertFile, ""),
		TLSKeyFile:   withDefaultEnv(envTLSKeyFile, ""),
		ChallengeMap: withDefaultEnv(envChallengeMap, ""),
		TTL:          defaultTTL,
		LogLevel:     withDefaultEnv(envLogLevel, defaultLogLevel),
		Gateway:      withDefaultEnv(envGateway, defaultGateway),
		CAFiles:      envPathList(envCAFile),
		Egress:       withDefaultEnv(envEgress, ""),
	}

	if v, ok := os.LookupEnv(envTTL); ok {
		ttl, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			f.envTTLErr = fmt.Errorf("invalid %s %q: give the TTL in seconds", envTTL, v)
		}

		f.TTL = uint32(ttl)
	}

	return f
}

// AddDaemonFlags registers the flags of the daemon.
func (f *Flags) AddDaemonFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Listen, flagListen, "", f.Listen,
		"TCP address the acme-dns API is served on (env "+envListen+")")
	flags.StringVarP(&f.TLSCertFile, flagTLSCertFile, "", f.TLSCertFile,
		"PEM certificate to serve HTTPS with, together with --"+flagTLSKeyFile+"; without both, plain HTTP is served (env "+envTLSCertFile+")")
	flags.StringVarP(&f.TLSKeyFile, flagTLSKeyFile, "", f.TLSKeyFile,
		"PEM private key of --"+flagTLSCertFile+" (env "+envTLSKeyFile+")")
	flags.StringVarP(&f.ChallengeMap, flagChallengeMap, "", f.ChallengeMap,
		"Challenge Map file, YAML or JSON, mapping each acme-dns subdomain to a zone and a name in it; required (env "+envChallengeMap+")")
	flags.Uint32VarP(&f.TTL, flagTTL, "", f.TTL,
		"TTL in seconds of the challenge values added (env "+envTTL+")")
	flags.StringVarP(&f.LogLevel, flagLogLevel, "", f.LogLevel,
		"lowest level of the logs written: "+logLevelNames()+" (env "+envLogLevel+")")
	flags.StringVarP(&f.Gateway, flagGateway, "", f.Gateway,
		"Gateway address as host:port (env "+envGateway+")")
	flags.StringArrayVarP(&f.CAFiles, flagCAFile, "", f.CAFiles,
		"PEM file of the CA certificates that verify the Gateway, instead of the system's; repeat it to trust several (env "+envCAFile+", a path list)")
	flags.StringVarP(&f.Egress, flagEgress, "", f.Egress,
		"Egress to reach the Provider through: gateway or agent (default: gateway if the token allows it; env "+envEgress+")")
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

// checkDaemonFlags checks the flags of the daemon, set on flags, and
// returns the ACME Endpoint's options they give. A TLS certificate without
// its key, or the reverse, is an error (acme.CheckTLSPair).
func checkDaemonFlags(f *Flags, flags *pflag.FlagSet) (acme.Options, error) {
	if err := acme.CheckTLSPair(f.TLSCertFile, f.TLSKeyFile); err != nil {
		return acme.Options{}, fmt.Errorf("--%s, --%s: %w", flagTLSCertFile, flagTLSKeyFile, err)
	}

	level, err := logLevel(f.LogLevel)
	if err != nil {
		return acme.Options{}, err
	}

	if f.envTTLErr != nil && !flags.Changed(flagTTL) {
		return acme.Options{}, f.envTTLErr
	}

	if f.ChallengeMap == "" {
		return acme.Options{}, errors.New("no Challenge Map: set --" + flagChallengeMap + " or " + envChallengeMap)
	}

	egress, err := gatewayconn.ParseEgress(f.Egress)
	if err != nil {
		return acme.Options{}, err
	}

	return acme.Options{
		Listen:           f.Listen,
		CertFile:         f.TLSCertFile,
		KeyFile:          f.TLSKeyFile,
		LogLevel:         level,
		Gateway:          f.Gateway,
		CAFiles:          f.CAFiles,
		Egress:           egress,
		ChallengeMapFile: f.ChallengeMap,
		TTL:              f.TTL,
	}, nil
}

// logLevel returns the slog level that name, a --log-level, names.
func logLevel(name string) (slog.Level, error) {
	for _, l := range logLevels {
		if l.name == name {
			return l.level, nil
		}
	}

	return 0, errors.New(`unknown log level "` + name + `": use ` + logLevelNames())
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}

// envPathList returns the paths in the environment variable key, a path
// list, leaving out empty entries.
func envPathList(key string) []string {
	var paths []string

	for _, p := range filepath.SplitList(os.Getenv(key)) {
		if p != "" {
			paths = append(paths, p)
		}
	}

	return paths
}
