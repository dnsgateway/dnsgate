// Package revocation keeps the IDs of revoked Service Tokens.
//
// The Gateway keeps no token registry (ADR 0001): a revoked token ID is
// the only thing it stores. A token is rejected if its own ID, or the ID
// of any of its ancestors, is revoked, so revoking a token also revokes
// every token derived from it.
package revocation

import (
	"context"
	"time"
)

// Entry is a revoked token ID and how long to keep it.
type Entry struct {
	// ID is the revoked token's ID.
	ID string
	// ExpiresAt is the token's expiry, after which the entry may be
	// purged. The zero time keeps the entry forever, for a token that
	// never expires or whose expiry is not known.
	ExpiresAt time.Time
}

// Store keeps revoked token IDs. SQLite implements it in v1; the
// interface leaves room for PostgreSQL.
type Store interface {
	// Revoke records e's ID as revoked. Revoking an ID again keeps its
	// entry as long as either revocation needs it.
	Revoke(ctx context.Context, e Entry) error
	// AnyRevoked reports whether any of ids is revoked.
	AnyRevoked(ctx context.Context, ids []string) (bool, error)
	// PurgeExpired removes the entries whose expiry is not after now: their
	// tokens no longer open anyway.
	PurgeExpired(ctx context.Context, now time.Time) error
}
