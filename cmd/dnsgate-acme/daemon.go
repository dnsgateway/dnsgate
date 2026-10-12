package main

import (
	"context"
	"io"

	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/acme"
)

// runDaemon checks the flags, set on flags, then serves the ACME Endpoint
// until ctx is done. Logs go to logOut as JSON lines. Its Gateway client
// takes clientOpts.
func runDaemon(ctx context.Context, logOut io.Writer, f *Flags, flags *pflag.FlagSet, clientOpts ...client.Option) error {
	opts, err := checkDaemonFlags(f, flags)
	if err != nil {
		return err
	}

	opts.Log = logOut
	opts.ClientOptions = clientOpts

	return acme.Run(ctx, opts)
}
