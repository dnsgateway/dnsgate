// Command dnsgate is the DNS Gateway CLI.
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
		Use:           bin,
		Short:         "DNS Gateway CLI",
		Long:          "dnsgate manages DNS records at a DNS Provider through the DNS Gateway.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	flags.AddPersistentFlags(rootCmd.PersistentFlags())

	rootCmd.AddCommand(
		newVersionCmd(),
	)

	return rootCmd
}
