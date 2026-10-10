package gatewayadapter

import (
	"errors"
	"net/http"

	"github.com/dnsgateway/dnsprovider"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
)

// apiProvider is what the Gateway Adapter's *dnsprovider.APIError values
// name as their Provider: dnscli registers it under this type.
const apiProvider = "dnsgate"

// kinds maps each Gateway error category to the typed Provider error it
// is; a category not here is classified by its provider_status alone.
var kinds = map[dnsgatev1.Error_Category]error{
	dnsgatev1.Error_CATEGORY_UNAUTHENTICATED:    dnsprovider.ErrUnauthorized,
	dnsgatev1.Error_CATEGORY_PERMISSION_DENIED:  dnsprovider.ErrUnauthorized,
	dnsgatev1.Error_CATEGORY_DENIED_BY_PROVIDER: dnsprovider.ErrUnauthorized,
	dnsgatev1.Error_CATEGORY_NOT_FOUND:          dnsprovider.ErrNotFound,
	dnsgatev1.Error_CATEGORY_RATE_LIMITED:       dnsprovider.ErrRateLimited,
	dnsgatev1.Error_CATEGORY_CONFLICT:           dnsprovider.ErrConflict,
}

// providerError maps the error of a Gateway call to a
// *dnsprovider.APIError: its category to the typed Provider error, an
// invalid request or record to HTTP status 400, any other to the
// Provider's HTTP status the Gateway reports, if any. The Gateway's
// message, which never quotes a secret, is its message. An error that
// carries no gRPC status, such as a canceled context, is returned as it
// is.
func providerError(err error) error {
	gwErr, ok := errors.AsType[*client.Error](err)
	if !ok {
		return err
	}

	detail := gwErr.Detail()

	out := &dnsprovider.APIError{
		Provider:   apiProvider,
		StatusCode: int(detail.GetProviderStatus()),
		Messages:   []string{gwErr.Error()},
		Kind:       kinds[detail.GetCategory()],
	}

	if c := detail.GetCategory(); c == dnsgatev1.Error_CATEGORY_INVALID_REQUEST || c == dnsgatev1.Error_CATEGORY_INVALID_RECORD {
		out.StatusCode = http.StatusBadRequest
	}

	return out
}
