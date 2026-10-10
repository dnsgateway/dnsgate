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

	"github.com/dnsgateway/dnsgate-go/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// dialGateway connects to the Gateway at --gateway over TLS, verifying it
// against the certificates of every --ca-file or, without one, the
// system's CA certificates. closeConn releases the connection.
func dialGateway(f *Flags) (c *client.Client, closeConn func(), err error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if len(f.CAFiles) > 0 {
		pool := x509.NewCertPool()

		for _, file := range f.CAFiles {
			pem, err := os.ReadFile(file)
			if err != nil {
				return nil, nil, fmt.Errorf("reading CA file: %w", err)
			}

			if !pool.AppendCertsFromPEM(pem) {
				return nil, nil, fmt.Errorf("CA file %s holds no PEM certificate", file)
			}
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

// printList prints a list as indented JSON on out and, if the Gateway
// marked it a Partial View, a note on errOut saying the token's
// Permissions do not cover uncovered, such as "every zone".
func printList(out, errOut io.Writer, list any, partial bool, uncovered string) error {
	if err := printJSON(out, list); err != nil {
		return err
	}

	if partial {
		_, _ = fmt.Fprintln(errOut, "note: partial view: the token's Permissions do not cover "+uncovered)
	}

	return nil
}
