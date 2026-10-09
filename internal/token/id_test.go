package token_test

import (
	"testing"

	"github.com/dnsgateway/dnsgate/internal/token"
)

func TestValidIDAcceptsOnlyThePrefixAndAULID(t *testing.T) {
	for id, want := range map[string]bool{
		"tok_01ARZ3NDEKTSV4RRFFQ69G5FAV":  true,
		"":                                false,
		"tok_":                            false,
		"01ARZ3NDEKTSV4RRFFQ69G5FAV":      false,
		"req_01ARZ3NDEKTSV4RRFFQ69G5FAV":  false,
		"tok_not-a-ulid":                  false,
		"tok_01ARZ3NDEKTSV4RRFFQ69G5FA":   false,
		"tok_01ARZ3NDEKTSV4RRFFQ69G5FAV0": false,
	} {
		if got := token.ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}
