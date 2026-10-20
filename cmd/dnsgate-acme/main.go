// Command dnsgate-acme runs the ACME Endpoint: it serves the acme-dns and
// acmeproxy APIs to ACME clients, over HTTPS or over plain HTTP behind a
// TLS-terminating proxy.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/spf13/cobra"
)

const bin = "dnsgate-acme"

// Set at build time through the Makefile's ldflags.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	err := newRootCmd().ExecuteContext(ctx)

	stop()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newRootCmd returns the dnsgate-acme command, whose Gateway client takes
// clientOpts: none in production, where it acts as Egress Agent through
// its host's network; tests give it a fake network.
func newRootCmd(clientOpts ...client.Option) *cobra.Command {
	flags := DefaultFlags()

	rootCmd := &cobra.Command{
		Use:   bin,
		Short: "ACME Endpoint",
		Long: "dnsgate-acme runs the ACME Endpoint: it serves the acme-dns and acmeproxy APIs to ACME clients on --" + flagListen + ". " +
			"Every write goes through the Gateway at --" + flagGateway + " with the caller's Service Token and the --" + flagEgress +
			" Egress. The Gateway does all the authorization.\n\n" +
			"acme-dns: POST /update adds the challenge value at the Challenge Target of the subdomain, " +
			"presenting the X-Api-Key Service Token, with its jti as X-Api-User. The optional --" + flagChallengeMap +
			" names the Challenge Target of a subdomain; " +
			"a subdomain it does not map, or every subdomain without it, is taken as the Certificate Domain and written at " +
			"_acme-challenge in front of it, in the longest zone of the token that holds that name.\n\n" +
			"acmeproxy: POST /present adds the challenge value at the fqdn of the JSON body {\"fqdn\", \"value\"}, " +
			"and POST /cleanup removes that value only, leaving any other value there. " +
			"Both take HTTP Basic auth: the username is the token's jti and the password is the Service Token. " +
			"The fqdn is the Challenge Target: the Challenge Map is not consulted, and the zone is the longest zone " +
			"of the token's Permissions that holds the fqdn.\n\n" +
			"GET /health answers 200 with an empty body. POST /register is not supported (404): " +
			"an Administrator provisions the tokens.\n\n" +
			"Logs are written to stderr as JSON lines. Logs below --" + flagLogLevel + " are dropped.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDaemon(cmd.Context(), cmd.ErrOrStderr(), flags, cmd.Flags(), clientOpts...)
		},
	}

	flags.AddDaemonFlags(rootCmd.Flags())

	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}
