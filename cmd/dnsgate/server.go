package main

import (
	"context"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/server"
)

// purgeInterval is how often the Gateway purges the entries of revoked
// tokens that have expired; zero means server.DefaultPurgeInterval. Tests
// shorten it.
var purgeInterval time.Duration

func newServerCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Gateway",
		Long: "Run the Gateway: serve its gRPC API on --" + flagListen + " over TLS with the certificate in --" + flagTLSCertFile +
			" and --" + flagTLSKeyFile + ", configured by a YAML file.\n\n" +
			"Audit events are written to stdout and logs to stderr, both as JSON lines. " +
			"Logs below --" + flagLogLevel + " are dropped; audit events are always written. " +
			"At debug, each request is logged when it ends, with its gRPC method, operation, request ID, peer address, duration and gRPC code.\n\n" +
			"Configuration file, with paths relative to its directory:\n\n" +
			"  keys:\n" +
			"    signingKeyFile: keys/sig-2026-10.pem\n" +
			"    encryptionKeyFile: keys/enc-2026-11.pem\n" +
			"    decryptionKeys:\n" +
			"      - keyFile: keys/enc-2026-10.pem\n" +
			"        retireAt: 2026-12-01T00:00:00Z\n" +
			"  bootstrapSecretFile: bootstrap-secret\n" +
			"  database:\n" +
			"    sqliteFile: dnsgate.db\n\n" +
			"The database holds only revoked token IDs. It is created if missing; keep it across restarts and " +
			"upgrades, or revoked tokens work again. Entries of revoked tokens that have expired are purged at startup " +
			"and every hour.\n\n" +
			"To rotate the encryption key:\n\n" +
			"  1. Run \"dnsgate keys generate\" with a new --" + flagKeyIDSuffix + ". Only its enc- key file is used; " +
			"ignore or delete the sig- key files it also writes, and keep signingKeyFile as it is.\n" +
			"  2. Make the new enc- file the encryptionKeyFile.\n" +
			"  3. Move the old encryptionKeyFile to decryptionKeys with a retireAt deadline, and restart the Gateway.\n" +
			"  4. Run \"dnsgate-cli token reseal\" on each token before the deadline.\n\n" +
			"New tokens are sealed under the current key. Tokens sealed under a decryption key open only " +
			"until its deadline; resealing moves them to the current key with the same signature.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServer(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), flags)
		},
	}

	flags.AddServerFlags(cmd.Flags())

	return cmd
}

// runServer checks the flags of "server", then serves the Gateway with the
// supported Providers until ctx is done.
func runServer(ctx context.Context, auditOut, logOut io.Writer, f *Flags) error {
	level, err := checkServerFlags(f)
	if err != nil {
		return err
	}

	return server.Run(ctx, server.Options{
		ConfigFile:    f.Config,
		Listen:        f.Listen,
		TLSCertFile:   f.TLSCertFile,
		TLSKeyFile:    f.TLSKeyFile,
		LogLevel:      level,
		Audit:         auditOut,
		Log:           logOut,
		Providers:     provider.Registry(),
		PurgeInterval: purgeInterval,
	})
}
