package main

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

const (
	flagGateway         = gatewayconn.FlagGateway
	flagCAFile          = gatewayconn.FlagCAFile
	flagToken           = "token"
	flagBootstrapSecret = "bootstrap-secret"
	flagCredential      = "provider-credential"
	flagProvider        = "provider"
	flagExpires         = "expires"
	flagZone            = "zone"
	flagEgress          = gatewayconn.FlagEgress
	flagSub             = "sub"
	flagPermissions     = "permissions"
	flagTTL             = "ttl"
	flagAdd             = "add"
	flagRemove          = "remove"
	flagExtra           = "extra"

	envGateway         = gatewayconn.EnvGateway
	envCAFile          = gatewayconn.EnvCAFile
	envToken           = "DNSGATE_TOKEN"
	envBootstrapSecret = "DNSGATE_BOOTSTRAP_SECRET"
	envCredential      = "DNSGATE_PROVIDER_CREDENTIAL"
	envZone            = "DNSGATE_ZONE"
	envEgress          = gatewayconn.EnvEgress
)

const defaultGateway = gatewayconn.DefaultGateway

// secretHelp is appended to the help of flags that take a secret.
const secretHelp = "; prefer the environment variable, a flag value shows in process listings"

// Flags holds the parsed CLI flags. Each falls back to an environment
// variable, then to a default, except --provider, --sub, --permissions and
// --expires, which are chosen per Onboarding or per Derived Token, and
// --ttl, --add and --remove, which are chosen per record change.
type Flags struct {
	Gateway string
	CAFiles []string
	Token   string

	BootstrapSecret string
	Credential      string
	Provider        string
	Expires         time.Duration

	Sub             string
	PermissionsFile string

	Zone   string
	Egress string

	TTL    uint32
	Add    []string
	Remove []string
	Extras []string
}

// DefaultFlags returns the flags resolved from the environment and
// defaults, before command-line parsing.
func DefaultFlags() *Flags {
	return &Flags{
		Gateway:         withDefaultEnv(envGateway, defaultGateway),
		CAFiles:         envPathList(envCAFile),
		Token:           withDefaultEnv(envToken, ""),
		BootstrapSecret: withDefaultEnv(envBootstrapSecret, ""),
		Credential:      withDefaultEnv(envCredential, ""),
		Zone:            withDefaultEnv(envZone, ""),
		Egress:          withDefaultEnv(envEgress, ""),
	}
}

// AddClientFlags registers the flags of every command that calls the
// Gateway.
func (f *Flags) AddClientFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Gateway, flagGateway, "", f.Gateway,
		"Gateway address as host:port (env "+envGateway+")")
	flags.StringArrayVarP(&f.CAFiles, flagCAFile, "", f.CAFiles,
		"PEM file of the CA certificates that verify the Gateway, instead of the system's; repeat it to trust several (env "+envCAFile+", a path list)")
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
	egress, err := gatewayconn.ParseEgress(f.Egress)
	if err != nil {
		return 0, err
	}

	if f.Token == "" {
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

// checkRecordFlags checks the flags of the record commands and returns
// the Egress asked for.
func checkRecordFlags(f *Flags) (dnsgatev1.Egress, error) {
	if f.Zone == "" {
		return 0, errors.New("no zone: set " + envZone + " or --" + flagZone)
	}

	return checkReadFlags(f)
}

// AddRecordWriteFlags registers the flags of "record create" and "record
// update": the record flags and the RRset's TTL.
func (f *Flags) AddRecordWriteFlags(flags *pflag.FlagSet) {
	flags.Uint32VarP(&f.TTL, flagTTL, "", f.TTL,
		"TTL of the records in seconds, such as 300; required")
	f.addExtraFlag(flags, "every VALUE")
	f.AddRecordFlags(flags)
}

// checkRecordWriteFlags checks the flags of "record create" and "record
// update" and returns the Egress asked for and values as records, each
// with the Record Extras the --extra flags set.
func checkRecordWriteFlags(f *Flags, values []string) (dnsgatev1.Egress, []*dnsgatev1.RecordValue, error) {
	if f.TTL == 0 {
		return 0, nil, errors.New("no TTL: set --" + flagTTL)
	}

	egress, err := checkRecordFlags(f)
	if err != nil {
		return 0, nil, err
	}

	records, err := f.recordValues(values)
	if err != nil {
		return 0, nil, err
	}

	return egress, records, nil
}

// AddRecordPatchFlags registers the flags of "record patch": the record
// flags, the values to add and remove, and the TTL of those added.
func (f *Flags) AddRecordPatchFlags(flags *pflag.FlagSet) {
	flags.StringArrayVarP(&f.Add, flagAdd, "", f.Add,
		"value to add to the RRset; repeat it to add several")
	flags.StringArrayVarP(&f.Remove, flagRemove, "", f.Remove,
		"value to remove from the RRset; repeat it to remove several")
	flags.Uint32VarP(&f.TTL, flagTTL, "", f.TTL,
		"TTL of the records added in seconds; required to create the RRset (default: the RRset's TTL)")
	f.addExtraFlag(flags, "every --"+flagAdd+" value")
	f.AddRecordFlags(flags)
}

// addExtraFlag registers --extra, which sets a Record Extra on the values
// that a record write gives, as its help names them in setOn.
func (f *Flags) addExtraFlag(flags *pflag.FlagSet, setOn string) {
	flags.StringArrayVarP(&f.Extras, flagExtra, "", f.Extras,
		"Record Extra KEY=VALUE to set on "+setOn+", such as proxied=true; KEY= clears it; repeat it to set several")
}

// recordValues returns values as records, each with the Record Extras
// the --extra flags set.
func (f *Flags) recordValues(values []string) ([]*dnsgatev1.RecordValue, error) {
	var extras map[string]string

	for _, kv := range f.Extras {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, errors.New("--" + flagExtra + " takes KEY=VALUE")
		}

		if extras == nil {
			extras = map[string]string{}
		}

		extras[k] = v
	}

	out := make([]*dnsgatev1.RecordValue, 0, len(values))
	for _, v := range values {
		out = append(out, &dnsgatev1.RecordValue{Value: v, Extras: maps.Clone(extras)})
	}

	return out, nil
}

// AddOnboardFlags registers the flags of "onboard".
func (f *Flags) AddOnboardFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Provider, flagProvider, "", f.Provider,
		"Provider the credential authenticates to: "+strings.Join(catalog.Names(), ", "))
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
		"YAML or JSON file of the Derived Token's Permissions, see the command help")
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

// envPathList returns the non-empty paths of the path list in the
// environment variable key, split with the OS list separator.
func envPathList(key string) []string {
	var paths []string

	for _, p := range filepath.SplitList(os.Getenv(key)) {
		if p != "" {
			paths = append(paths, p)
		}
	}

	return paths
}
