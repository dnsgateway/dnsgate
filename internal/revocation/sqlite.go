package revocation

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// schema creates the one table: revoked token IDs, each with the Unix
// time, in seconds, from which its entry may be purged, or NULL to keep
// it forever.
const schema = `CREATE TABLE IF NOT EXISTS revoked_tokens (
	id         TEXT PRIMARY KEY,
	expires_at INTEGER
) STRICT`

// SQLite is a Store in an SQLite database file.
type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// OpenSQLite opens the SQLite database file at path, creating it and its
// table if they are missing. Its directory must exist.
func OpenSQLite(ctx context.Context, path string) (*SQLite, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening revocation database %s: %w", path, err)
	}

	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("opening revocation database %s: %w", path, err)
	}

	return &SQLite{db: db}, nil
}

// Close closes the database.
func (s *SQLite) Close() error {
	return s.db.Close()
}

// Revoke implements Store.
func (s *SQLite) Revoke(ctx context.Context, e Entry) error {
	var exp sql.NullInt64
	if !e.ExpiresAt.IsZero() {
		exp = sql.NullInt64{Int64: ceilUnix(e.ExpiresAt), Valid: true}
	}

	_, err := s.db.ExecContext(ctx, `INSERT INTO revoked_tokens (id, expires_at) VALUES (?, ?)
		ON CONFLICT (id) DO UPDATE SET expires_at = CASE
			WHEN expires_at IS NULL OR excluded.expires_at IS NULL THEN NULL
			ELSE max(expires_at, excluded.expires_at)
		END`, e.ID, exp)
	if err != nil {
		return fmt.Errorf("revoking token: %w", err)
	}

	return nil
}

// AnyRevoked implements Store.
func (s *SQLite) AnyRevoked(ctx context.Context, ids []string) (bool, error) {
	if len(ids) == 0 {
		return false, nil
	}

	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}

	query := `SELECT EXISTS (SELECT 1 FROM revoked_tokens WHERE id IN (?` +
		strings.Repeat(", ?", len(ids)-1) + `))`

	var revoked bool
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&revoked); err != nil {
		return false, fmt.Errorf("checking revoked tokens: %w", err)
	}

	return revoked, nil
}

// PurgeExpired implements Store.
func (s *SQLite) PurgeExpired(ctx context.Context, now time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE expires_at <= ?`, now.Unix()); err != nil {
		return fmt.Errorf("purging expired revocations: %w", err)
	}

	return nil
}

// ceilUnix returns t in Unix seconds, rounded up, so an entry is never
// purged before its token's expiry.
func ceilUnix(t time.Time) int64 {
	sec := t.Unix()
	if t.Nanosecond() > 0 {
		sec++
	}

	return sec
}
