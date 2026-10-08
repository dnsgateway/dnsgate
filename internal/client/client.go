// Package client calls the Gateway's gRPC API, one Call stream per
// request.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// Client sends requests to a Gateway.
type Client struct {
	api dnsgatev1.GatewayServiceClient
}

// New returns a Client that calls the Gateway over conn.
func New(conn grpc.ClientConnInterface) *Client {
	return &Client{api: dnsgatev1.NewGatewayServiceClient(conn)}
}

// Onboard turns a Provider Credential into a Root Token.
func (c *Client) Onboard(ctx context.Context, req *dnsgatev1.OnboardRequest) (*dnsgatev1.OnboardResponse, error) {
	return roundTrip(ctx, c, "onboard",
		&dnsgatev1.Request{Operation: &dnsgatev1.Request_Onboard{Onboard: req}},
		(*dnsgatev1.Response).GetOnboard)
}

// InspectToken asks the Gateway to show the content of tok.
func (c *Client) InspectToken(ctx context.Context, tok string) (*dnsgatev1.InspectTokenResponse, error) {
	return roundTrip(ctx, c, "inspect",
		&dnsgatev1.Request{Operation: &dnsgatev1.Request_InspectToken{InspectToken: &dnsgatev1.InspectTokenRequest{Token: tok}}},
		(*dnsgatev1.Response).GetInspectToken)
}

// ResealToken asks the Gateway to reseal tok under its current encryption
// key.
func (c *Client) ResealToken(ctx context.Context, tok string) (*dnsgatev1.ResealTokenResponse, error) {
	return roundTrip(ctx, c, "reseal",
		&dnsgatev1.Request{Operation: &dnsgatev1.Request_ResealToken{ResealToken: &dnsgatev1.ResealTokenRequest{Token: tok}}},
		(*dnsgatev1.Response).GetResealToken)
}

// roundTrip sends req, named op in errors, and returns the result that
// result picks from the Response. A Response holding another operation's
// result is an error.
func roundTrip[R any](ctx context.Context, c *Client, op string, req *dnsgatev1.Request, result func(*dnsgatev1.Response) *R) (*R, error) {
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}

	out := result(resp)
	if out == nil {
		return nil, fmt.Errorf("gateway answered %s with another operation", op)
	}

	return out, nil
}

// call opens a stream, sends req and waits for its Response. A Gateway
// error comes back as an *Error holding the status that ended the stream.
func (c *Client) call(ctx context.Context, req *dnsgatev1.Request) (*dnsgatev1.Response, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.api.Call(ctx)
	if err != nil {
		return nil, newError(err)
	}

	if err := stream.Send(&dnsgatev1.CallRequest{Message: &dnsgatev1.CallRequest_Request{Request: req}}); err != nil && !errors.Is(err, io.EOF) {
		return nil, newError(err)
	}

	// A failed Send returns io.EOF; the reason is the status Recv returns.
	if err := stream.CloseSend(); err != nil {
		return nil, newError(err)
	}

	msg, err := stream.Recv()
	if err != nil {
		return nil, newError(err)
	}

	resp := msg.GetResponse()
	if resp == nil {
		return nil, fmt.Errorf("gateway sent %T, want a response", msg.GetMessage())
	}

	return resp, nil
}
