package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// callGateway dials the Gateway, calls the client operation op with arg
// and closes the connection. A failed call's error is prefixed with name.
func callGateway[A, R any](ctx context.Context, f *Flags, name string, op func(*client.Client, context.Context, A) (R, error), arg A) (R, error) {
	var zero R

	c, closeConn, err := dialGateway(f)
	if err != nil {
		return zero, err
	}

	defer closeConn()

	resp, err := op(c, ctx, arg)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", name, err)
	}

	return resp, nil
}

// printJSON prints v as indented JSON.
func printJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	return enc.Encode(v)
}
