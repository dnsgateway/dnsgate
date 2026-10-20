// Package acme runs the ACME Endpoint: an HTTP server that speaks the
// acme-dns and acmeproxy APIs to ACME clients, over HTTPS or over plain
// HTTP behind a TLS-terminating proxy.
package acme

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"

	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
)

// DefaultListen is the address the ACME Endpoint serves on, unless Options
// set another address.
const DefaultListen = ":8080"

// Bounds of each request. acme-dns requests are small JSON objects and
// each one needs at most a few Gateway round trips.
const (
	// MaxBodyBytes caps a request body; a larger body is refused.
	MaxBodyBytes = 4 << 10

	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	WriteTimeout      = 30 * time.Second
	IdleTimeout       = 60 * time.Second

	// shutdownTimeout bounds how long a stop waits for requests in flight.
	shutdownTimeout = 10 * time.Second
)

// Options configure an ACME Endpoint run.
type Options struct {
	// Listen is the TCP address the API is served on; empty means
	// DefaultListen.
	Listen string
	// CertFile and KeyFile are the PEM certificate and key served over
	// HTTPS. Both empty serves plain HTTP; only one of them is an error.
	CertFile string
	KeyFile  string
	// LogLevel is the lowest level of the logs written.
	LogLevel slog.Level
	// Log receives the logs as JSON lines.
	Log io.Writer

	// Gateway is the Gateway's address, host:port, and CAFiles the PEM
	// files of the CAs that verify it; none means the system's.
	Gateway string
	CAFiles []string
	// Egress is the Egress every write asks for; unspecified lets the
	// Gateway choose.
	Egress dnsgatev1.Egress
	// ChallengeMapFile is the Challenge Map file, YAML or JSON; empty means
	// no Challenge Map, so every subdomain is unmapped.
	ChallengeMapFile string
	// TTL is the TTL of the challenge values added.
	TTL uint32
	// ClientOptions configure the Gateway client. Without
	// client.WithEgressAgent, the ACME Endpoint relays Agent Egress
	// through its host's resolver and network, under the destination
	// rules of ADR 0002, which no option lifts.
	ClientOptions []client.Option
}

// Config holds what the API handler needs.
type Config struct {
	// Logger receives the handler's logs.
	Logger *slog.Logger
	// Gateway is the client every write calls.
	Gateway *client.Client
	// ChallengeMap maps the acme-dns subdomains to Challenge Targets.
	ChallengeMap ChallengeMap
	// TTL is the TTL of the challenge values added.
	TTL uint32
	// Egress is the Egress every write asks for.
	Egress dnsgatev1.Egress
}

// NewHandler returns the acme-dns and acmeproxy APIs. acme-dns: POST
// /update adds a challenge value through the Gateway, and /register is
// not supported (404) because tokens are provisioned by an Administrator.
// acmeproxy: POST /present adds a challenge value at the fqdn through the
// Gateway. GET /health answers 200 with an empty body. Request bodies are
// capped at MaxBodyBytes.
func NewHandler(c Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/register", http.NotFound)

	p := patcher{gateway: c.Gateway, egress: c.Egress}

	mux.Handle("POST /update", updateEndpoint(c.Logger, &updater{patcher: p, targets: c.ChallengeMap, change: present(c.TTL)}))
	mux.Handle("POST /present", acmeproxyEndpoint(c.Logger, "present", &acmeproxy{patcher: p, change: present(c.TTL)}))

	return http.MaxBytesHandler(mux, MaxBodyBytes)
}

// Run serves the ACME Endpoint until ctx is done, then stops gracefully.
// A TLS certificate without its key, or the reverse, files that do not
// load, or a given Challenge Map file that does not, stop it before it
// listens. It connects to the Gateway lazily, on the first write.
func Run(ctx context.Context, o Options) error {
	tlsConfig, err := loadTLS(o.CertFile, o.KeyFile)
	if err != nil {
		return err
	}

	var targets ChallengeMap
	if o.ChallengeMapFile != "" {
		targets, err = LoadChallengeMap(o.ChallengeMapFile)
		if err != nil {
			return err
		}
	}

	gateway, closeConn, err := gatewayconn.Dial(o.Gateway, o.CAFiles, o.ClientOptions...)
	if err != nil {
		return err
	}

	defer closeConn()

	log := slog.New(slog.NewJSONHandler(o.Log, &slog.HandlerOptions{Level: o.LogLevel}))

	listen := o.Listen
	if listen == "" {
		listen = DefaultListen
	}

	log.Debug("configured", "listen", listen, "tls", tlsConfig != nil)

	srv := &http.Server{
		Handler: NewHandler(Config{
			Logger:       log,
			Gateway:      gateway,
			ChallengeMap: targets,
			TTL:          o.TTL,
			Egress:       o.Egress,
		}),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", listen)
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}

	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
		lis = tls.NewListener(lis, tlsConfig)
	}

	log.Info("serving", "address", lis.Addr().String(), "scheme", scheme)

	served := make(chan error, 1)

	go func() { served <- srv.Serve(lis) }()

	select {
	case err := <-served:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()

		err := srv.Shutdown(stopCtx)

		if serveErr := <-served; !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}

		if err != nil {
			return fmt.Errorf("stopping: %w", err)
		}

		log.Info("stopped")

		return nil
	}
}

// CheckTLSPair returns an error if only one of certFile and keyFile is
// given, so a half-configured HTTPS setup never falls back to plain HTTP.
func CheckTLSPair(certFile, keyFile string) error {
	if (certFile == "") != (keyFile == "") {
		return errors.New("a TLS certificate and key must be given together: give both to serve HTTPS, or neither to serve plain HTTP")
	}

	return nil
}

// loadTLS returns the TLS configuration that serves certFile and keyFile,
// or nil for plain HTTP when both are empty.
func loadTLS(certFile, keyFile string) (*tls.Config, error) {
	if err := CheckTLSPair(certFile, keyFile); err != nil {
		return nil, err
	}

	if certFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Some ACME clients and Proxmox run older TLS stacks.
		MinVersion: tls.VersionTLS12,
	}, nil
}
