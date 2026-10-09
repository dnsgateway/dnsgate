package token

import (
	"strings"

	"github.com/oklog/ulid/v2"
)

// IDPrefix starts every token ID. No sealed Service Token starts with it,
// so it also tells a token ID from a token.
const IDPrefix = "tok_"

// ValidID reports whether id has the form of a token ID: IDPrefix and a
// ULID.
func ValidID(id string) bool {
	rest, ok := strings.CutPrefix(id, IDPrefix)
	if !ok {
		return false
	}

	_, err := ulid.ParseStrict(rest)

	return err == nil
}
