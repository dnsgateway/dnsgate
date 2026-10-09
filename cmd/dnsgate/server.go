package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/config"
	"github.com/dnsgateway/dnsgate/internal/gateway"
	"github.com/dnsgateway/dnsgate/internal/provider"
	"github.com/dnsgateway/dnsgate/internal/revocation"
)

// purgeInterval is how often the Gateway purges the revocations of
// tokens that have expired. Tests shorten it.
var purgeInterval = time.Hour

// providers returns the Providers the Gateway calls. Tests replace it with
// a fake Provider.
var providers = provider.Registry

func newServerCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Gateway",
		Long: "Run the Gateway: serve its gRPC API over TLS, configured by a YAML file.\n\n" +
			"Audit events are written to stdout and logs to stderr, both as JSON lines. " +
			"Logs below --" + flagLogLevel + " are dropped; audit events are always written. " +
			"At debug, each request is logged when it ends, with its gRPC method, operation, request ID, peer address, duration and gRPC code.\n\n" +
			"Configuration file, with paths relative to its directory:\n\n" +
			"  listen: \":8443\"\n" +
			"  tls:\n" +
			"    certFile: tls.crt\n" +
			"    keyFile: tls.key\n" +
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
			"upgrades, or revoked tokens work again. Revocations of tokens that have expired are purged at startup " +
			"and every hour.\n\n" +
			"To rotate the encryption key:\n\n" +
			"  1. Run \"dnsgate keys generate\" with a new --" + flagKeyIDSuffix + ". Only its enc- key file is used; " +
			"ignore or delete the sig- key files it also writes, and keep signingKeyFile as it is.\n" +
			"  2. Make the new enc- file the encryptionKeyFile.\n" +
			"  3. Move the old encryptionKeyFile to decryptionKeys with a retireAt deadline, and restart the Gateway.\n" +
			"  4. Run \"dnsgate token reseal\" on each token before the deadline.\n\n" +
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

// runServer serves the Gateway until ctx is done, then stops gracefully.
// Any configuration problem, such as a missing or loosely permitted key
// file, stops it before it listens.
func runServer(ctx context.Context, auditOut, logOut io.Writer, f *Flags) error {
	level, err := checkServerFlags(f)
	if err != nil {
		return err
	}

	cfg, err := config.Load(f.Config)
	if err != nil {
		return err
	}

	src, err := cfg.Keys.Load()
	if err != nil {
		return err
	}

	secret, err := cfg.BootstrapSecret()
	if err != nil {
		return err
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}

	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: level}))
	log.Debug("loaded config", "file", f.Config, "listen", cfg.Listen)

	revocations, err := revocation.OpenSQLite(ctx, cfg.Database.SQLiteFile)
	if err != nil {
		return err
	}

	defer revocations.Close()

	if err := revocations.PurgeExpired(ctx, time.Now()); err != nil {
		return err
	}

	go purgeRevocations(ctx, revocations, purgeInterval, log)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})))

	dnsgatev1.RegisterGatewayServiceServer(srv, gateway.New(gateway.Config{
		Keys:            src,
		BootstrapSecret: secret,
		Audit:           audit.New(auditOut),
		Providers:       providers(),
		MaxAncestors:    cfg.Tokens.MaxAncestors,
		Revocations:     revocations,
		Logger:          log,
	}))

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}

	log.Info("serving", "address", lis.Addr().String())

	served := make(chan error, 1)

	go func() { served <- srv.Serve(lis) }()

	select {
	case err := <-served:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
		srv.GracefulStop()
		<-served

		log.Info("stopped")

		return nil
	}
}

// purgeRevocations purges, every interval until ctx is done, the
// revocations of tokens that have expired. A failed purge is logged and
// retried at the next interval: the entries it leaves only take space.
func purgeRevocations(ctx context.Context, store revocation.Store, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := store.PurgeExpired(ctx, now); err != nil && ctx.Err() == nil {
				log.Error("purging expired revocations", "error", err)
			}
		}
	}
}
