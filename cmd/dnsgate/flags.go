package main

import (
	"os"
	"time"

	"github.com/spf13/pflag"
)

const (
	flagKeyDir          = "key-dir"
	flagKeyIDSuffix     = "key-id-suffix"
	flagConfig          = "config"
	flagGateway         = "gateway"
	flagCAFile          = "ca-file"
	flagToken           = "token"
	flagBootstrapSecret = "bootstrap-secret"
	flagCredential      = "provider-credential"
	flagProvider        = "provider"
	flagExpires         = "expires"

	envKeyDir          = "DNSGATE_KEY_DIR"
	envKeyIDSuffix     = "DNSGATE_KEY_ID_SUFFIX"
	envConfig          = "DNSGATE_CONFIG"
	envGateway         = "DNSGATE_GATEWAY"
	envCAFile          = "DNSGATE_CA_FILE"
	envToken           = "DNSGATE_TOKEN"
	envBootstrapSecret = "DNSGATE_BOOTSTRAP_SECRET"
	envCredential      = "DNSGATE_PROVIDER_CREDENTIAL"
)

const (
	defaultKeyDir      = "keys"
	defaultKeyIDSuffix = ""
	defaultConfig      = "dnsgate.yaml"
	defaultGateway     = "localhost:8443"
)

// secretHelp is appended to the help of flags that take a secret.
const secretHelp = "; prefer the environment variable, a flag value shows in process listings"

// Flags holds the parsed CLI flags. Each falls back to an environment
// variable, then to a default, except --provider and --expires, which are
// chosen per Onboarding.
type Flags struct {
	KeyDir      string
	KeyIDSuffix string

	Config string

	Gateway string
	CAFile  string
	Token   string

	BootstrapSecret string
	Credential      string
	Provider        string
	Expires         time.Duration
}

// DefaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func DefaultFlags() *Flags {
	return &Flags{
		KeyDir:          withDefaultEnv(envKeyDir, defaultKeyDir),
		KeyIDSuffix:     withDefaultEnv(envKeyIDSuffix, defaultKeyIDSuffix),
		Config:          withDefaultEnv(envConfig, defaultConfig),
		Gateway:         withDefaultEnv(envGateway, defaultGateway),
		CAFile:          withDefaultEnv(envCAFile, ""),
		Token:           withDefaultEnv(envToken, ""),
		BootstrapSecret: withDefaultEnv(envBootstrapSecret, ""),
		Credential:      withDefaultEnv(envCredential, ""),
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
}

// AddClientFlags registers the flags of every command that calls the
// Gateway.
func (f *Flags) AddClientFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Gateway, flagGateway, "", f.Gateway,
		"Gateway address as host:port (env "+envGateway+")")
	flags.StringVarP(&f.CAFile, flagCAFile, "", f.CAFile,
		"PEM file of the CA certificates that verify the Gateway, instead of the system's (env "+envCAFile+")")
}

// AddTokenFlags registers the flag of commands that present a Service
// Token.
func (f *Flags) AddTokenFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Token, flagToken, "", f.Token,
		"Service Token to present (env "+envToken+secretHelp+")")
}

// AddOnboardFlags registers the flags of "onboard".
func (f *Flags) AddOnboardFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Provider, flagProvider, "", f.Provider,
		"Provider the credential authenticates to: cloudflare")
	flags.StringVarP(&f.Credential, flagCredential, "", f.Credential,
		"Provider Credential, a Cloudflare API token (env "+envCredential+secretHelp+")")
	flags.StringVarP(&f.BootstrapSecret, flagBootstrapSecret, "", f.BootstrapSecret,
		"bootstrap secret configured on the Gateway (env "+envBootstrapSecret+secretHelp+")")
	flags.DurationVarP(&f.Expires, flagExpires, "", f.Expires,
		"lifetime of the Root Token, such as 720h (default: never expires)")
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}
