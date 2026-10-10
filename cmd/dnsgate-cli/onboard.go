package main

import (
	"context"
	"errors"
	"fmt"
	"io"

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
	credType, ok := catalog.CredentialType(f.Provider)

	switch {
	case f.Provider == "":
		return errors.New("no provider: set --" + flagProvider)
	case !ok:
		return fmt.Errorf("unsupported provider %q", f.Provider)
	case f.BootstrapSecret == "":
		return errors.New("no bootstrap secret: set " + envBootstrapSecret + " or --" + flagBootstrapSecret)
	case f.Credential == "":
		return errors.New("no Provider Credential: set " + envCredential + " or --" + flagCredential)
	}

	req := &dnsgatev1.OnboardRequest{
		BootstrapSecret: f.BootstrapSecret,
		Provider:        f.Provider,
		Credential:      &dnsgatev1.Credential{Type: credType, Value: f.Credential},
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
