package dnsgatev1

import (
	"strings"

	"google.golang.org/grpc/status"
)

// ErrorDetail returns the Error detail of st, or nil if it has none.
func ErrorDetail(st *status.Status) *Error {
	for _, d := range st.Details() {
		if e, ok := d.(*Error); ok {
			return e
		}
	}

	return nil
}

// Name returns the category's enum name in lower case without the
// prefix, such as "unauthenticated" or "permission_denied".
func (c Error_Category) Name() string {
	return strings.ToLower(strings.TrimPrefix(c.String(), "CATEGORY_"))
}
