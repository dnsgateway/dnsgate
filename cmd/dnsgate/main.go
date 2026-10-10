// Command dnsgate runs the DNS Gateway and manages its keys. The commands
// that call the Gateway are in dnsgate-cli.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

const bin = "dnsgate"

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
		Use:   bin,
		Short: "DNS Gateway",
		Long: "dnsgate runs the Gateway and manages its keys.\n\n" +
			"To call the Gateway, use dnsgate-cli: onboard, token, zone and record.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(
		newKeysCmd(flags),
		newServerCmd(flags),
		newVersionCmd(),
	)

	return rootCmd
}
