package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/config"
	"github.com/dnsgateway/dnsgate/internal/gateway"
	"github.com/dnsgateway/dnsgate/internal/keys"
)

func newServerCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Gateway",
		Long: "Run the Gateway: serve its gRPC API over TLS, configured by a YAML file.\n\n" +
			"Audit events are written to stdout and logs to stderr, both as JSON lines.\n\n" +
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
			"  bootstrapSecretFile: bootstrap-secret\n\n" +
			"To rotate the encryption key, generate a new key set with \"dnsgate keys generate\" and a new " +
			"--" + flagKeyIDSuffix + ", make its enc- file the encryptionKeyFile and move the old one to decryptionKeys with a retireAt deadline. New tokens " +
			"are sealed under the current key; tokens sealed under an older key open until its deadline, " +
			"and \"dnsgate token reseal\" moves them to the current key.",
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
	cfg, err := config.Load(f.Config)
	if err != nil {
		return err
	}

	opts := make([]keys.Option, 0, len(cfg.Keys.DecryptionKeys))
	for _, dk := range cfg.Keys.DecryptionKeys {
		opts = append(opts, keys.WithDecryptionKey(dk.KeyFile, dk.RetireAt))
	}

	src, err := keys.LoadFiles(cfg.Keys.SigningKeyFile, cfg.Keys.EncryptionKeyFile, opts...)
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

	log := slog.New(slog.NewJSONHandler(logOut, nil))

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})))

	dnsgatev1.RegisterGatewayServiceServer(srv, gateway.New(gateway.Config{
		Keys:            src,
		BootstrapSecret: secret,
		Audit:           audit.New(auditOut),
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
