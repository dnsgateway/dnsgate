package main

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/provider"
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
	flagZone            = "zone"
	flagEgress          = "egress"
	flagSub             = "sub"
	flagPermissions     = "permissions"

	envKeyDir          = "DNSGATE_KEY_DIR"
	envKeyIDSuffix     = "DNSGATE_KEY_ID_SUFFIX"
	envConfig          = "DNSGATE_CONFIG"
	envGateway         = "DNSGATE_GATEWAY"
	envCAFile          = "DNSGATE_CA_FILE"
	envToken           = "DNSGATE_TOKEN"
	envBootstrapSecret = "DNSGATE_BOOTSTRAP_SECRET"
	envCredential      = "DNSGATE_PROVIDER_CREDENTIAL"
	envZone            = "DNSGATE_ZONE"
	envEgress          = "DNSGATE_EGRESS"
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
// variable, then to a default, except --provider, --sub, --permissions and
// --expires, which are chosen per Onboarding or per Derived Token.
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

	Sub             string
	PermissionsFile string

	Zone   string
	Egress string
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
		Zone:            withDefaultEnv(envZone, ""),
		Egress:          withDefaultEnv(envEgress, ""),
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

// AddReadFlags registers the flags of every zone and record command: they
// present a Service Token to the Gateway to reach the Provider.
func (f *Flags) AddReadFlags(flags *pflag.FlagSet) {
	f.AddTokenFlags(flags)
	flags.StringVarP(&f.Egress, flagEgress, "", f.Egress,
		"Egress to reach the Provider through: gateway or agent (default: gateway if the token allows it; env "+envEgress+")")
	f.AddClientFlags(flags)
}

// checkReadFlags checks the flags every zone and record command takes and
// returns the Egress asked for.
func checkReadFlags(f *Flags) (dnsgatev1.Egress, error) {
	egress, ok := permission.Egress(f.Egress).API()

	switch {
	case !ok:
		return 0, errors.New(`unknown egress "` + f.Egress + `": use gateway or agent`)
	case f.Token == "":
		return 0, errors.New("no Service Token: set " + envToken + " or --" + flagToken)
	}

	return egress, nil
}

// AddRecordFlags registers the flags of every record command: the read
// flags and the zone the records are in.
func (f *Flags) AddRecordFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Zone, flagZone, "", f.Zone,
		"zone the records are in, such as example.com (env "+envZone+")")
	f.AddReadFlags(flags)
}

// AddOnboardFlags registers the flags of "onboard".
func (f *Flags) AddOnboardFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Provider, flagProvider, "", f.Provider,
		"Provider the credential authenticates to: "+strings.Join(provider.Names(), ", "))
	flags.StringVarP(&f.Credential, flagCredential, "", f.Credential,
		"Provider Credential, such as a Cloudflare API token (env "+envCredential+secretHelp+")")
	flags.StringVarP(&f.BootstrapSecret, flagBootstrapSecret, "", f.BootstrapSecret,
		"bootstrap secret configured on the Gateway (env "+envBootstrapSecret+secretHelp+")")
	flags.DurationVarP(&f.Expires, flagExpires, "", f.Expires,
		"lifetime of the Root Token, such as 720h (default: never expires)")
}

// AddTokenCreateFlags registers the flags of "token create".
func (f *Flags) AddTokenCreateFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Sub, flagSub, "", f.Sub,
		"Service Account the Derived Token is issued for, such as external-dns-prod")
	flags.StringVarP(&f.PermissionsFile, flagPermissions, "", f.PermissionsFile,
		"YAML file of the Derived Token's Permissions, see the command help")
	flags.DurationVarP(&f.Expires, flagExpires, "", f.Expires,
		"lifetime of the Derived Token, such as 720h; required if the Parent Token expires (default: never expires)")
	f.AddTokenFlags(flags)
	f.AddClientFlags(flags)
}

// checkTokenCreateFlags checks the flags of "token create".
func checkTokenCreateFlags(f *Flags) error {
	switch {
	case f.Token == "":
		return errors.New("no Parent Token: set " + envToken + " or --" + flagToken)
	case f.Sub == "":
		return errors.New("no Service Account: set --" + flagSub)
	case f.PermissionsFile == "":
		return errors.New("no Permissions: set --" + flagPermissions)
	case f.Expires < 0:
		return errors.New("--" + flagExpires + " must not be negative")
	}

	return nil
}

func withDefaultEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}

	return def
}
