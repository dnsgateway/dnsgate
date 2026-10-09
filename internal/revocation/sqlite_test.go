package revocation_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/revocation"
)

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func openSQLite(t *testing.T, path string) *revocation.SQLite {
	t.Helper()

	s, err := revocation.OpenSQLite(t.Context(), path)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}

	t.Cleanup(func() { _ = s.Close() })

	return s
}

func anyRevoked(t *testing.T, s revocation.Store, ids ...string) bool {
	t.Helper()

	got, err := s.AnyRevoked(t.Context(), ids)
	if err != nil {
		t.Fatalf("AnyRevoked: %v", err)
	}

	return got
}

func revoke(t *testing.T, s revocation.Store, id string, expiresAt time.Time) {
	t.Helper()

	if err := s.Revoke(t.Context(), id, expiresAt); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestAnyRevokedFindsARevokedIDAmongOthers(t *testing.T) {
	s := openSQLite(t, filepath.Join(t.TempDir(), "dnsgate.db"))

	if anyRevoked(t, s, "tok_A", "tok_B") {
		t.Error("an empty store reports a revoked ID")
	}

	if anyRevoked(t, s) {
		t.Error("no IDs reported as revoked")
	}

	revoke(t, s, "tok_B", time.Time{})

	if !anyRevoked(t, s, "tok_A", "tok_B", "tok_C") {
		t.Error("tok_B is revoked, but not reported")
	}

	if anyRevoked(t, s, "tok_A", "tok_C") {
		t.Error("IDs that were never revoked are reported")
	}
}

func TestRevokedIDsSurviveReopening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsgate.db")

	s := openSQLite(t, path)
	revoke(t, s, "tok_A", time.Time{})
	revoke(t, s, "tok_B", now.Add(time.Hour))

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openSQLite(t, path)

	for _, id := range []string{"tok_A", "tok_B"} {
		if !anyRevoked(t, reopened, id) {
			t.Errorf("%s is no longer revoked after reopening", id)
		}
	}
}

func TestPurgeExpiredRemovesOnlyEntriesWhoseExpiryHasPassed(t *testing.T) {
	s := openSQLite(t, filepath.Join(t.TempDir(), "dnsgate.db"))

	revoke(t, s, "tok_forever", time.Time{})
	revoke(t, s, "tok_expired", now.Add(-time.Second))
	revoke(t, s, "tok_at_now", now)
	revoke(t, s, "tok_later", now.Add(time.Second))

	if err := s.PurgeExpired(t.Context(), now); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}

	for id, want := range map[string]bool{
		"tok_forever": true,
		"tok_expired": false,
		// A token is invalid from its exp on, so its entry may go then.
		"tok_at_now": false,
		"tok_later":  true,
	} {
		if got := anyRevoked(t, s, id); got != want {
			t.Errorf("%s revoked after purge = %v, want %v", id, got, want)
		}
	}
}

func TestRevokingAgainKeepsTheEntryAsLongAsEitherRevocationNeedsIt(t *testing.T) {
	for name, tc := range map[string]struct {
		first, second time.Time
		keptAt        time.Time
	}{
		"by token, then by ID": {first: now.Add(time.Hour), second: time.Time{}, keptAt: now.Add(1000 * time.Hour)},
		"by ID, then by token": {first: time.Time{}, second: now.Add(time.Hour), keptAt: now.Add(1000 * time.Hour)},
		"earlier, then later":  {first: now.Add(time.Hour), second: now.Add(2 * time.Hour), keptAt: now.Add(90 * time.Minute)},
		"later, then earlier":  {first: now.Add(2 * time.Hour), second: now.Add(time.Hour), keptAt: now.Add(90 * time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			s := openSQLite(t, filepath.Join(t.TempDir(), "dnsgate.db"))

			revoke(t, s, "tok_A", tc.first)
			revoke(t, s, "tok_A", tc.second)

			if err := s.PurgeExpired(t.Context(), tc.keptAt); err != nil {
				t.Fatal(err)
			}

			if !anyRevoked(t, s, "tok_A") {
				t.Error("the entry was purged while a revocation still needs it")
			}
		})
	}
}

func TestOpenSQLiteFailsForAnUnusablePath(t *testing.T) {
	if _, err := revocation.OpenSQLite(t.Context(), filepath.Join(t.TempDir(), "missing", "dnsgate.db")); err == nil {
		t.Error("OpenSQLite in a missing directory succeeded")
	}
}
