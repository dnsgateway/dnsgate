package main

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"

	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/acme"
	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
	"github.com/dnsgateway/dnsgate/internal/loglevel"
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
	defaultLogLevel = slog.LevelInfo
	defaultGateway  = gatewayconn.DefaultGateway
)

// envVar is the environment variable of a flag. A path list is split,
// leaving out empty entries, and gives the flag once per path.
type envVar struct {
	flag, env string
	pathList  bool
}

// daemonFlags registers the flags of the daemon on flags, bound to the
// ACME Endpoint's options with their built-in defaults, and returns the
// function that gives those options once flags are parsed. That function
// first gives each flag not set on the command line the value of its
// environment variable, if set, through the same parse: a bad value in
// the environment is an error unless the flag replaces it.
func daemonFlags(flags *pflag.FlagSet) func(lookupEnv func(string) (string, bool)) (acme.Options, error) {
	opts := acme.Options{TTL: defaultTTL, LogLevel: defaultLogLevel}

	envVars := append(addEndpointFlags(flags, &opts), addGatewayFlags(flags, &opts)...)

	return func(lookupEnv func(string) (string, bool)) (acme.Options, error) {
		for _, e := range envVars {
			value, ok := lookupEnv(e.env)
			if !ok || flags.Changed(e.flag) {
				continue
			}

			values := []string{value}
			if e.pathList {
				values = pathList(value)
			}

			for _, v := range values {
				if err := flags.Set(e.flag, v); err != nil {
					return acme.Options{}, envError(e, v, err)
				}
			}
		}

		return opts, nil
	}
}

// addEndpointFlags registers the flags of the ACME Endpoint itself,
// bound to opts, and returns their environment variables.
func addEndpointFlags(flags *pflag.FlagSet, opts *acme.Options) []envVar {
	flags.StringVarP(&opts.Listen, flagListen, "", defaultListen,
		"TCP address the acme-dns and acmeproxy APIs are served on (env "+envListen+")")
	flags.StringVarP(&opts.CertFile, flagTLSCertFile, "", "",
		"PEM certificate to serve HTTPS with, together with --"+flagTLSKeyFile+"; without both, plain HTTP is served (env "+envTLSCertFile+")")
	flags.StringVarP(&opts.KeyFile, flagTLSKeyFile, "", "",
		"PEM private key of --"+flagTLSCertFile+" (env "+envTLSKeyFile+")")
	flags.StringVarP(&opts.ChallengeMapFile, flagChallengeMap, "", "",
		"Challenge Map file, YAML or JSON, mapping each acme-dns subdomain to a zone and a name in it, "+
			"or, with no zone, to a name in any zone the token allows; without it, every subdomain is unmapped (env "+envChallengeMap+")")
	flags.VarP(ttlValue{&opts.TTL}, flagTTL, "",
		"TTL in seconds of the challenge values added (env "+envTTL+")")
	flags.VarP(loglevel.NewValue(&opts.LogLevel), flagLogLevel, "",
		"lowest level of the logs written: "+loglevel.Names()+" (env "+envLogLevel+")")

	return []envVar{
		{flag: flagListen, env: envListen},
		{flag: flagTLSCertFile, env: envTLSCertFile},
		{flag: flagTLSKeyFile, env: envTLSKeyFile},
		{flag: flagChallengeMap, env: envChallengeMap},
		{flag: flagTTL, env: envTTL},
		{flag: flagLogLevel, env: envLogLevel},
	}
}

// addGatewayFlags registers the flags that point the Gateway client at
// the Gateway, bound to opts, and returns their environment variables.
func addGatewayFlags(flags *pflag.FlagSet, opts *acme.Options) []envVar {
	flags.StringVarP(&opts.Gateway, flagGateway, "", defaultGateway,
		"Gateway address as host:port (env "+envGateway+")")
	flags.StringArrayVarP(&opts.CAFiles, flagCAFile, "", nil,
		"PEM file of the CA certificates that verify the Gateway, instead of the system's; repeat it to trust several (env "+envCAFile+", a path list)")
	flags.VarP(gatewayconn.NewEgressValue(&opts.Egress), flagEgress, "",
		"Egress to reach the Provider through: gateway or agent (default: gateway if the token allows it; env "+envEgress+")")

	return []envVar{
		{flag: flagGateway, env: envGateway},
		{flag: flagCAFile, env: envCAFile, pathList: true},
		{flag: flagEgress, env: envEgress},
	}
}

// ttlValue is a --ttl flag: a TTL in seconds.
type ttlValue struct {
	ttl *uint32
}

func (v ttlValue) Set(value string) error {
	ttl, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return errors.New("give the TTL in seconds")
	}

	*v.ttl = uint32(ttl)

	return nil
}

func (v ttlValue) String() string {
	return strconv.FormatUint(uint64(*v.ttl), 10)
}

// Type is "uint32", so the help shows a --ttl as one.
func (v ttlValue) Type() string {
	return "uint32"
}

// flagError returns err, an error parsing the flags. A bad --egress gives
// gatewayconn's message alone, the one dnsgate-cli gives, which already
// names the value.
func flagError(err error) error {
	if invalid, ok := errors.AsType[*pflag.InvalidValueError](err); ok && invalid.GetFlag().Name == flagEgress {
		return invalid.Unwrap()
	}

	return err
}

// envError returns the error of value, from e's environment variable,
// that its flag refused with err: "<ENV> "<value>": <reason>", or, for
// --egress, gatewayconn's message alone, as flagError gives it.
func envError(e envVar, value string, err error) error {
	if invalid, ok := errors.AsType[*pflag.InvalidValueError](err); ok {
		err = invalid.Unwrap()
	}

	if e.flag == flagEgress {
		return err
	}

	return fmt.Errorf("%s %q: %w", e.env, value, err)
}

// pathList returns the paths in list, a path list, leaving out empty
// entries.
func pathList(list string) []string {
	var paths []string

	for _, p := range filepath.SplitList(list) {
		if p != "" {
			paths = append(paths, p)
		}
	}

	return paths
}
