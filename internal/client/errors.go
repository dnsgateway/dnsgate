package client

import (
	"strings"

	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// Error is a failed Gateway request. Its gRPC status stays reachable
// through status.FromError.
type Error struct {
	status *status.Status
	detail *dnsgatev1.Error
}

// newError wraps the error a stream ended with. Errors that carry no gRPC
// status, such as a canceled context, are returned as they are.
func newError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	return &Error{status: st, detail: dnsgatev1.ErrorDetail(st)}
}

// Error returns the Gateway error category and message, such as
// "unauthenticated: wrong or missing bootstrap secret". An error without a
// Gateway category, such as a connection failure, shows its gRPC code.
func (e *Error) Error() string {
	if e.detail == nil {
		return strings.ToLower(e.status.Code().String()) + ": " + e.status.Message()
	}

	return strings.ReplaceAll(e.detail.GetCategory().Name(), "_", " ") + ": " + e.status.Message()
}

// Detail returns the Gateway's Error detail, or nil if there was none.
func (e *Error) Detail() *dnsgatev1.Error { return e.detail }

// GRPCStatus returns the status the stream ended with.
func (e *Error) GRPCStatus() *status.Status { return e.status }
