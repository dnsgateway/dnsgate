// Package catalog names the Providers the Gateway supports, the fields
// each is built from and the types of Provider Credential each onboards.
// It links no Provider implementation, so clients can import it without
// them.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// The supported Providers, by name.
const (
	Cloudflare   = "cloudflare"
	ClouDNS      = "cloudns"
	DigitalOcean = "digitalocean"
	DNSimple     = "dnsimple"
	Gandi        = "gandi"
	GoDaddy      = "godaddy"
	Hetzner      = "hetzner"
	InternetBS   = "internetbs" //nolint:misspell // the Provider's name
	Namecheap    = "namecheap"
	OVHcloud     = "ovhcloud"
	Porkbun      = "porkbun"
	Scaleway     = "scaleway"
	Vultr        = "vultr"
)

// The types of Provider Credential.
const (
	// TypeFields is a JSON object mapping the Provider's field names to
	// their values. Every Provider onboards it.
	TypeFields = "fields"
	// TypeAPIToken is a Cloudflare API token alone, as Root Tokens
	// onboarded before TypeFields carry it.
	TypeAPIToken = "api-token"
)

// Field is one field a Provider is built from.
type Field struct {
	// Name is the key in the Provider's field map, e.g. "token".
	Name string
	// Label is for people, e.g. "API token".
	Label string
	// Secret marks a field to keep out of process listings.
	Secret bool
}

// fields maps each supported Provider to the fields it is built from, in
// the order of its Factory.
var fields = map[string][]Field{
	Cloudflare: {
		{Name: "token", Label: "API token", Secret: true},
		{Name: "tenant_id", Label: "Account ID"},
	},
	ClouDNS: {
		{Name: "password", Label: "API password", Secret: true},
		{Name: "auth_id", Label: "API authentication ID", Secret: true},
		{Name: "sub_auth_id", Label: "Sub-user authentication ID", Secret: true},
		{Name: "sub_auth_user", Label: "Sub-user username", Secret: true},
	},
	DigitalOcean: {{Name: "token", Label: "API token", Secret: true}},
	DNSimple: {
		{Name: "token", Label: "API token", Secret: true},
		{Name: "account_id", Label: "Account ID"},
	},
	Gandi:   {{Name: "token", Label: "Personal access token", Secret: true}},
	GoDaddy: {{Name: "token", Label: "Personal access token", Secret: true}},
	Hetzner: {{Name: "token", Label: "Project API token", Secret: true}},
	InternetBS: {
		{Name: "key", Label: "API key", Secret: true},
		{Name: "password", Label: "API password", Secret: true},
	},
	Namecheap: {
		{Name: "user", Label: "API user"},
		{Name: "key", Label: "API key", Secret: true},
		{Name: "client_ip", Label: "Whitelisted client IPv4"},
	},
	OVHcloud: {
		{Name: "application_key", Label: "Application key", Secret: true},
		{Name: "application_secret", Label: "Application secret", Secret: true},
		{Name: "consumer_key", Label: "Consumer key", Secret: true},
		{Name: "endpoint", Label: "API endpoint (ovh-eu, ovh-ca or ovh-us)"},
	},
	Porkbun: {
		{Name: "key", Label: "API key", Secret: true},
		{Name: "secret", Label: "Secret API key", Secret: true},
	},
	Scaleway: {
		{Name: "secret_key", Label: "Secret key", Secret: true},
		{Name: "project_id", Label: "Project ID"},
	},
	Vultr: {{Name: "api_key", Label: "API key", Secret: true}},
}

// apiTokenField is the field a TypeAPIToken credential fills.
const apiTokenField = "token"

// Names returns the names of the supported Providers, sorted.
func Names() []string {
	return slices.Sorted(maps.Keys(fields))
}

// Fields returns the fields the Provider name is built from, and whether
// name is a supported Provider.
func Fields(name string) ([]Field, bool) {
	fs, ok := fields[name]

	return slices.Clone(fs), ok
}

// SoleSecret returns the name of the Provider's one secret field, for a
// credential given as a single value. It reports false for an unsupported
// Provider and for one with several secret fields.
func SoleSecret(name string) (string, bool) {
	var sole string

	for _, f := range fields[name] {
		if !f.Secret {
			continue
		}

		if sole != "" {
			return "", false
		}

		sole = f.Name
	}

	return sole, sole != ""
}

// Accepts reports whether the Provider name onboards a Provider Credential
// of type typ.
func Accepts(name, typ string) bool {
	if _, ok := fields[name]; !ok {
		return false
	}

	return typ == TypeFields || (typ == TypeAPIToken && name == Cloudflare)
}

// EncodeFields returns the value of a TypeFields credential holding m. It
// refuses a field the Provider name does not take, and a map with no
// value.
func EncodeFields(name string, m map[string]string) (string, error) {
	if err := checkFields(name, m); err != nil {
		return "", err
	}

	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// DecodeCredential returns the field map the Provider name is built from
// with a Provider Credential of type typ and value. The map holds the
// plaintext credential, and errors never quote it.
func DecodeCredential(name, typ, value string) (map[string]string, error) {
	if !Accepts(name, typ) {
		return nil, fmt.Errorf("provider %q does not take a %q credential", name, typ)
	}

	if typ == TypeAPIToken {
		if value == "" {
			return nil, errors.New("empty credential")
		}

		return map[string]string{apiTokenField: value}, nil
	}

	var m map[string]string
	if err := json.Unmarshal([]byte(value), &m); err != nil {
		return nil, errors.New("credential is not a JSON object of string fields")
	}

	if err := checkFields(name, m); err != nil {
		return nil, err
	}

	return m, nil
}

// checkFields refuses a field the Provider name does not take, and a map
// with no value. The error names fields, never their values.
func checkFields(name string, m map[string]string) error {
	fs, ok := fields[name]
	if !ok {
		return fmt.Errorf("unsupported provider %q", name)
	}

	var unknown []string

	set := false

	for k, v := range m {
		if !slices.ContainsFunc(fs, func(f Field) bool { return f.Name == k }) {
			unknown = append(unknown, k)
		}

		set = set || v != ""
	}

	if len(unknown) > 0 {
		slices.Sort(unknown)

		return fmt.Errorf("provider %q takes no field %s", name, strings.Join(unknown, ", "))
	}

	if !set {
		return errors.New("empty credential")
	}

	return nil
}
