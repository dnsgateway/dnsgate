// Package server starts the Gateway: it loads the YAML configuration,
// builds the Gateway and serves its gRPC API over TLS until it is told to
// stop.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/config"
	"github.com/dnsgateway/dnsgate/internal/gateway"
	"github.com/dnsgateway/dnsgate/internal/revocation"
)

// DefaultPurgeInterval is how often a Gateway purges the entries of
// revoked tokens that have expired, unless Options set another interval.
const DefaultPurgeInterval = time.Hour

// Options configure a Gateway run.
type Options struct {
	// ConfigFile is the Gateway's YAML configuration file.
	ConfigFile string
	// LogLevel is the lowest level of the logs written.
	LogLevel slog.Level
	// Audit receives the audit events, as JSON lines.
	Audit io.Writer
	// Log receives the logs, as JSON lines.
	Log io.Writer
	// Providers are the Providers the Gateway calls.
	Providers dnsprovider.Registry
	// PurgeInterval is how often the entries of revoked tokens that have
	// expired are purged; zero means DefaultPurgeInterval.
	PurgeInterval time.Duration
}

// Run serves the Gateway until ctx is done, then stops gracefully. Any
// configuration problem, such as a missing or loosely permitted key file,
// stops it before it listens.
func Run(ctx context.Context, o Options) error {
	cfg, err := config.Load(o.ConfigFile)
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

	log := slog.New(slog.NewJSONHandler(o.Log, &slog.HandlerOptions{Level: o.LogLevel}))
	log.Debug("loaded config", "file", o.ConfigFile, "listen", cfg.Listen)

	revokedIDs, err := revocation.OpenSQLite(ctx, cfg.Database.SQLiteFile)
	if err != nil {
		return err
	}

	defer revokedIDs.Close()

	if err := revokedIDs.PurgeExpired(ctx, time.Now()); err != nil {
		return err
	}

	interval := o.PurgeInterval
	if interval <= 0 {
		interval = DefaultPurgeInterval
	}

	go purgeExpiredEntries(ctx, revokedIDs, interval, log)

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})))

	dnsgatev1.RegisterGatewayServiceServer(srv, gateway.New(gateway.Config{
		Keys:            src,
		BootstrapSecret: secret,
		Audit:           audit.New(o.Audit),
		Providers:       o.Providers,
		MaxAncestors:    cfg.Tokens.MaxAncestors,
		RevokedIDs:      revokedIDs,
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

// purgeExpiredEntries purges, every interval until ctx is done, the
// entries of revoked tokens that have expired. A failed purge is logged and
// retried at the next interval: the entries it leaves only take space.
func purgeExpiredEntries(ctx context.Context, store revocation.Store, interval time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := store.PurgeExpired(ctx, now); err != nil && ctx.Err() == nil {
				log.Error("purging expired entries", "error", err)
			}
		}
	}
}
