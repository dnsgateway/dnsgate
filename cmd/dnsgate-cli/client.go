package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/dnsgateway/dnsgate-go/client"

	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
)

// callGateway dials the Gateway, calls the client operation op with arg
// and closes the connection. A failed call's error is prefixed with name.
func callGateway[A, R any](ctx context.Context, f *Flags, name string, op func(*client.Client, context.Context, A) (R, error), arg A) (R, error) {
	var zero R

	c, closeConn, err := gatewayconn.Dial(f.Gateway, f.CAFiles)
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
