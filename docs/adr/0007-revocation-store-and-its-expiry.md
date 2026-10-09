# Revoked token IDs live behind a store interface, in an SQLite file the configuration must name, kept until the revoked token's own expiry

The Gateway keeps revoked token IDs behind a small store interface: `Revoke(entry)`, `AnyRevoked(ids)` and `PurgeExpired(now)`, where an entry is a token ID and its expiry. v1 implements it with SQLite (`modernc.org/sqlite`, no cgo) in one table of IDs, each with the Unix time from which it may be purged, or none to keep it forever. The Gateway configuration names the file as `database.sqliteFile`. The setting is required and has no default. The file is created if missing, in a directory that must exist.

The expiry of an entry comes from the revoked token itself. `RevokeTokenRequest` names its target either by `token_id` or by `target_token`. The target is parsed only once the presented token is opened and allowed `delete` on `tokens`, so a denied request learns nothing of it and its audit event names none. Given the token, the Gateway opens it (without the revocation check, so a token can be revoked again) and keeps the entry until the token's `exp`, or forever if it has none. Given only an ID, the Gateway has no registry to look the expiry up in (ADR 0001), so it keeps the entry forever. Revoking an ID again keeps the entry as long as either revocation needs it. The Gateway purges expired entries at startup and every hour.

Every request is refused, as unauthenticated ("revoked service token"), if its token's `jti` or any of its `ancestors` is in the store. The check runs right after the codec's claim checks and before Permissions, for every operation that presents a token, Resealing included. If the store cannot answer, the request is refused.

## Considered Options

- A default database path: rejected. A Gateway started with its configuration moved, or in a new container without the volume, would silently open an empty database, and every revoked token would work again. Requiring the setting makes that mistake visible in the configuration. A wrong but valid path still creates an empty file, which the server help warns about.
- Revocation by ID only, with entries kept forever: rejected. The table would only grow, which the draft rules out for tokens with an expiry.
- A maximum token lifetime used as the expiry of ID-only entries: rejected. A token may have no expiry at all, so no bound is safe.
- Withholding the revocation when its audit event is lost, as `token.create` withholds the new token: rejected. A revocation only takes access away. It is kept, and the lost event is logged.

## Consequences

- PostgreSQL can be added as a second implementation of the same interface, with a new `database` setting next to `sqliteFile`.
- The database holds only token IDs and expiry times, as the threat model says.
- An Administrator who wants an entry purged has to revoke with the token, not only its ID. `dnsgate token revoke -` reads the token from stdin, so it stays out of process listings.
- A token that no longer opens (expired, tampered, or sealed under a retired key) can be revoked only by its ID.
