package gateway

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// Error messages never quote what the client sent: it may hold a secret.

func invalidRequest(msg string) error {
	return gatewayError(codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST, msg)
}

func unauthenticated(msg string) error {
	return gatewayError(codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED, msg)
}

func internal() error {
	return gatewayError(codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL, "internal error")
}

// gatewayError returns a status error with an Error detail.
func gatewayError(code codes.Code, category dnsgatev1.Error_Category, msg string) error {
	st, err := status.New(code, msg).WithDetails(&dnsgatev1.Error{Category: category})
	if err != nil {
		return status.Error(code, msg)
	}

	return st.Err()
}

// category returns the category of a Gateway error for audit events, as
// its enum name in lower case without the prefix, such as
// "unauthenticated" or "permission_denied".
func category(err error) string {
	c := dnsgatev1.Error_CATEGORY_UNSPECIFIED

	for _, d := range status.Convert(err).Details() {
		if e, ok := d.(*dnsgatev1.Error); ok {
			c = e.GetCategory()

			break
		}
	}

	return strings.ToLower(strings.TrimPrefix(c.String(), "CATEGORY_"))
}
