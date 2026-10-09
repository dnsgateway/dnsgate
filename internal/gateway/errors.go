package gateway

import (
	"errors"
	"net/http"

	"github.com/dnsgateway/dnsprovider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/permission"
)

// Error messages never quote what the client sent: it may hold a secret.

func invalidRequest(msg string) error {
	return statusError(codes.InvalidArgument, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INVALID_REQUEST}, msg)
}

func unauthenticated(msg string) error {
	return statusError(codes.Unauthenticated, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_UNAUTHENTICATED}, msg)
}

func permissionDenied(msg string) error {
	return statusError(codes.PermissionDenied, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_PERMISSION_DENIED}, msg)
}

// narrowingViolation is the error of a Derived Token that would exceed its
// Parent Token in dimension, such as "zones" or "exp".
func narrowingViolation(dimension permission.Dimension) error {
	return statusError(codes.PermissionDenied,
		&dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_NARROWING_VIOLATION, Dimension: string(dimension)},
		"the token would exceed its parent token in "+string(dimension))
}

func agentEgressNotSupported() error {
	return statusError(codes.Unimplemented, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_EGRESS_NOT_SUPPORTED}, "agent egress is not supported yet")
}

func notFound(msg string) error {
	return statusError(codes.NotFound, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_NOT_FOUND}, msg)
}

func internal() error {
	return statusError(codes.Internal, &dnsgatev1.Error{Category: dnsgatev1.Error_CATEGORY_INTERNAL}, "internal error")
}

// statusError returns a status error with an Error detail.
func statusError(code codes.Code, detail *dnsgatev1.Error, msg string) error {
	st, err := status.New(code, msg).WithDetails(detail)
	if err != nil {
		return status.Error(code, msg)
	}

	return st.Err()
}

// providerError maps the error of a Provider call to a Gateway error that
// carries the Provider's HTTP status, if it answered with one. The
// Provider's own messages never reach the client.
func providerError(err error) error {
	detail := &dnsgatev1.Error{ProviderStatus: int32(providerStatus(err))}

	var (
		code codes.Code
		msg  string
	)

	switch {
	case errors.Is(err, dnsprovider.ErrRateLimited):
		code, detail.Category, msg = codes.ResourceExhausted, dnsgatev1.Error_CATEGORY_RATE_LIMITED, "rate limited by the provider"
	case errors.Is(err, dnsprovider.ErrUnauthorized):
		code, detail.Category, msg = codes.PermissionDenied, dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER, "the provider denied the request"
	case errors.Is(err, dnsprovider.ErrNotFound):
		code, detail.Category, msg = codes.NotFound, dnsgatev1.Error_CATEGORY_NOT_FOUND, "not found at the provider"
	case errors.Is(err, dnsprovider.ErrConflict), detail.ProviderStatus == http.StatusBadRequest,
		detail.ProviderStatus == http.StatusUnprocessableEntity:
		code, detail.Category, msg = codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_RECORD, "the provider rejected the record"
	default:
		code, detail.Category, msg = codes.Unavailable, dnsgatev1.Error_CATEGORY_INTERNAL, "the provider request failed"
	}

	return statusError(code, detail, msg)
}

// providerStatus returns the HTTP status of a Provider's error answer, or
// zero if err is not one.
func providerStatus(err error) int {
	if apiErr, ok := errors.AsType[*dnsprovider.APIError](err); ok {
		return apiErr.StatusCode
	}

	return 0
}

// category returns the category of a Gateway error for audit events, as
// its enum name in lower case without the prefix, such as
// "unauthenticated" or "permission_denied".
func category(err error) audit.Category {
	return audit.Category(dnsgatev1.ErrorDetail(status.Convert(err)).GetCategory().Name())
}
