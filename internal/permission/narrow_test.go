package permission_test

import (
	"testing"

	"github.com/dnsgateway/dnsgate/internal/permission"
)

func TestCoversName(t *testing.T) {
	for _, tc := range []struct {
		parent []string
		child  string
		want   bool
	}{
		{[]string{"@"}, "@", true},
		{[]string{"@"}, "www", false},
		{[]string{"www"}, "@", false},
		{[]string{"www"}, "www", true},
		{[]string{"WWW"}, "www", true},
		{[]string{"www"}, "*", false},
		{[]string{"*"}, "www", true},
		{[]string{"*"}, "@", false},
		{[]string{"*"}, "*", true},
		{[]string{"*"}, "**", false},
		{[]string{"*"}, "www.apps", false},
		{[]string{"**"}, "@", false},
		{[]string{"**"}, "www", true},
		{[]string{"**"}, "*", true},
		{[]string{"**"}, "a.b.c", true},
		{[]string{"**"}, "**.*", true},
		{[]string{"*.apps"}, "www.apps", true},
		{[]string{"*.apps"}, "*.apps", true},
		{[]string{"*.apps"}, "**.apps", false},
		{[]string{"*.apps"}, "apps", false},
		{[]string{"**.apps"}, "*.apps", true},
		{[]string{"**.apps"}, "a.*.apps", true},
		{[]string{"**.apps"}, "**.apps", true},
		{[]string{"**.apps"}, "apps", false},
		{[]string{"**.apps"}, "**", false},
		{[]string{"*.**"}, "**.**", true},
		{[]string{"*.**"}, "**", false},
		{[]string{"**.**"}, "*.**", true},
		{[]string{"a.**.z"}, "a.b.*.z", true},
		{[]string{"a.**.z"}, "a.z", false},
		{[]string{"_acme-challenge.**"}, "_acme-challenge", false},
		{[]string{"_acme-challenge", "_acme-challenge.**"}, "_acme-challenge", true},
		{nil, "www", false},

		// A pattern may be covered only by several parent patterns together.
		{[]string{"@", "**"}, "@", true},
		{[]string{"*", "*.**"}, "**", true},
		{[]string{"*", "*.*"}, "**", false},
		{[]string{"www.*", "*.*"}, "*.*", true},
		{[]string{"a.*", "*.b"}, "*.*", false},
	} {
		if got := permission.CoversName(tc.parent, tc.child); got != tc.want {
			t.Errorf("CoversName(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}
