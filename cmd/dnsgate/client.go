package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dnsgateway/dnsgate/internal/client"
)

// dialGateway connects to the Gateway at --gateway over TLS, verifying it
// against --ca-file or the system's CA certificates. closeConn releases the
// connection.
func dialGateway(f *Flags) (c *client.Client, closeConn func(), err error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if f.CAFile != "" {
		pem, err := os.ReadFile(f.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("reading CA file: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, nil, fmt.Errorf("CA file %s holds no PEM certificate", f.CAFile)
		}

		tlsCfg.RootCAs = pool
	}

	if f.Gateway == "" {
		return nil, nil, errors.New("no Gateway address: set --" + flagGateway + " or " + envGateway)
	}

	conn, err := grpc.NewClient(f.Gateway, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to the Gateway: %w", err)
	}

	return client.New(conn), func() { _ = conn.Close() }, nil
}
