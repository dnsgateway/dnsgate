package main

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
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

// daemonFlags are the flags of the daemon, bound to the ACME Endpoint's
// options, and their environment variables.
type daemonFlags struct {
	flags   *pflag.FlagSet
	opts    acme.Options
	envVars []envVar
}

// bindDaemonFlags registers the flags of the daemon on cmd, with their
// built-in defaults and the error func that words a bad flag, and returns
// them to give the options once cmd has parsed them.
func bindDaemonFlags(cmd *cobra.Command) *daemonFlags {
	f := &daemonFlags{
		flags: cmd.Flags(),
		opts:  acme.Options{TTL: defaultTTL, LogLevel: defaultLogLevel},
	}

	f.envVars = append(addEndpointFlags(f.flags, &f.opts), addGatewayFlags(f.flags, &f.opts)...)

	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return flagError(err) })

	return f
}

// options returns the ACME Endpoint's options. It first gives each flag
// not set on the command line the value of its environment variable, if
// set, through the same parse: a bad value in the environment is an
// error unless the flag replaces it.
func (f *daemonFlags) options(lookupEnv func(string) (string, bool)) (acme.Options, error) {
	for _, e := range f.envVars {
		value, ok := lookupEnv(e.env)
		if !ok || f.flags.Changed(e.flag) {
			continue
		}

		values := []string{value}
		if e.pathList {
			values = pathList(value)
		}

		for _, v := range values {
			if err := f.flags.Set(e.flag, v); err != nil {
				return acme.Options{}, envError(e, v, err)
			}
		}
	}

	return f.opts, nil
}

// runError returns err, the error of acme.Run, with a TLS certificate
// without its key, or the reverse, worded in flag terms.
func runError(err error) error {
	if errors.Is(err, acme.ErrTLSPair) {
		return fmt.Errorf("--%s, --%s: %w", flagTLSCertFile, flagTLSKeyFile, err)
	}

	return err
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

// valueNamer is a flag value whose Set errors are complete messages that
// name the value refused, such as gatewayconn's EgressValue: they are
// given alone, without the flag or environment variable in front.
type valueNamer interface {
	ErrorNamesValue() bool
}

// refusal returns the reason in err, an error setting a flag, and
// whether that reason is a complete message to give alone.
func refusal(err error) (reason error, complete bool) {
	invalid, ok := errors.AsType[*pflag.InvalidValueError](err)
	if !ok {
		return err, false
	}

	namer, ok := invalid.GetFlag().Value.(valueNamer)

	return invalid.Unwrap(), ok && namer.ErrorNamesValue()
}

// flagError returns err, an error parsing the flags, or the reason alone
// if it is a complete message.
func flagError(err error) error {
	if reason, complete := refusal(err); complete {
		return reason
	}

	return err
}

// envError returns the error of value, from e's environment variable,
// that its flag refused with err: "<ENV> "<value>": <reason>", or the
// reason alone if it is a complete message.
func envError(e envVar, value string, err error) error {
	reason, complete := refusal(err)
	if complete {
		return reason
	}

	return fmt.Errorf("%s %q: %w", e.env, value, reason)
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
