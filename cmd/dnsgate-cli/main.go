// Command dnsgate-cli calls the DNS Gateway: it onboards Provider
// Credentials, issues and manages Service Tokens, and reads and changes
// DNS records through the Gateway.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

const bin = "dnsgate-cli"

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

func newRootCmd() *cobra.Command {
	flags := DefaultFlags()

	rootCmd := &cobra.Command{
		Use:           bin,
		Short:         "DNS Gateway CLI",
		Long:          "dnsgate-cli manages DNS records at a Provider through the Gateway.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(
		newOnboardCmd(flags),
		newRecordCmd(flags),
		newTokenCmd(flags),
		newVersionCmd(),
		newZoneCmd(flags),
	)

	return rootCmd
}
