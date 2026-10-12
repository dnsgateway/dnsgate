package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dnsgateway/dnsgate/internal/provider/catalog"
)

func newOnboardCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "onboard",
		Short: "Turn a Provider Credential into a Root Token",
		Long: "Send a Provider Credential and the Gateway's bootstrap secret to the Gateway, " +
			"and print the Root Token it returns. The Root Token holds full Permissions and, " +
			"unless --" + flagExpires + " is set, never expires.\n\n" +
			"Set each field of the Provider with --" + flagProviderField + " NAME=VALUE or the " +
			"environment variable " + envProviderFieldPrefix + "<NAME>, such as " + envProviderFieldPrefix +
			"API_KEY; the flag wins. For a Provider with one secret field, --" + flagCredential +
			" (env " + envCredential + ") sets it unless a field does. The Provider fields:\n\n" +
			providerFieldsHelp() + "\n" +
			"The credential travels over the TLS connection to the Gateway, so it must not " +
			"pass through a proxy that terminates TLS.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOnboard(cmd.Context(), cmd.OutOrStdout(), flags)
		},
	}

	flags.AddOnboardFlags(cmd.Flags())
	flags.AddClientFlags(cmd.Flags())

	return cmd
}

func runOnboard(ctx context.Context, out io.Writer, f *Flags) error {
	switch {
	case f.Provider == "":
		return errors.New("no provider: set --" + flagProvider)
	case f.BootstrapSecret == "":
		return errors.New("no bootstrap secret: set " + envBootstrapSecret + " or --" + flagBootstrapSecret)
	}

	fields, err := providerFields(f)
	if err != nil {
		return err
	}

	value, err := catalog.EncodeFields(f.Provider, fields)
	if err != nil {
		return fmt.Errorf("no Provider Credential: %w; set --%s or %s<NAME>, see --help",
			err, flagProviderField, envProviderFieldPrefix)
	}

	req := &dnsgatev1.OnboardRequest{
		BootstrapSecret: f.BootstrapSecret,
		Provider:        f.Provider,
		Credential:      &dnsgatev1.Credential{Type: catalog.TypeFields, Value: value},
	}

	if f.Expires != 0 {
		req.Expires = durationpb.New(f.Expires)
	}

	resp, err := callGateway(ctx, f, "onboard", (*client.Client).Onboard, req)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, resp.GetToken())

	return err
}

// providerFields returns the fields of the Provider f names, from its
// environment variables, then --provider-field, then --provider-credential
// for a Provider with one secret field that neither set.
func providerFields(f *Flags) (map[string]string, error) {
	known, ok := catalog.Fields(f.Provider)
	if !ok {
		return nil, fmt.Errorf("unsupported provider %q, want one of %s", f.Provider, strings.Join(catalog.Names(), ", "))
	}

	fields := map[string]string{}

	for _, field := range known {
		if v := os.Getenv(envProviderFieldPrefix + strings.ToUpper(field.Name)); v != "" {
			fields[field.Name] = v
		}
	}

	for _, kv := range f.ProviderFields {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, errors.New("--" + flagProviderField + " takes NAME=VALUE")
		}

		fields[k] = v
	}

	if f.Credential == "" {
		return fields, nil
	}

	secret, ok := catalog.SoleSecret(f.Provider)
	if !ok {
		return nil, fmt.Errorf("provider %q takes several secret fields: set them with --%s, not --%s",
			f.Provider, flagProviderField, flagCredential)
	}

	if fields[secret] == "" {
		fields[secret] = f.Credential
	}

	return fields, nil
}

// providerFieldsHelp lists each Provider's fields, one Provider a line.
func providerFieldsHelp() string {
	var b strings.Builder

	for _, name := range catalog.Names() {
		known, _ := catalog.Fields(name)

		parts := make([]string, 0, len(known))
		for _, field := range known {
			part := field.Name + " (" + field.Label
			if field.Secret {
				part += ", secret"
			}

			parts = append(parts, part+")")
		}

		fmt.Fprintf(&b, "  %-13s %s\n", name, strings.Join(parts, ", "))
	}

	return b.String()
}
