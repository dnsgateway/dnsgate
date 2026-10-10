# dnsgate through the Gateway Adapter in dnscli

Research note: how the multi-provider DNS editor `dnscli` (`../dnscli`) can
manage records through the Gateway (this repo), by way of a Gateway Adapter.
The Gateway itself is never a Provider (`GLOSSARY.md`). Where the adapter
lives is recorded in `docs/adr/0008-gateway-adapter-in-dnsgate.md`.

Sources are the three sibling repos as checked out on 2026-10-09:

- `dnsgate` (this repo, module `github.com/dnsgateway/dnsgate`)
- `dnscli` (`../dnscli`, module `github.com/sergelogvinov/dnscli`)
- `dnsprovider` (`../dnsprovider`, module `github.com/dnsgateway/dnsprovider`),
  the shared Provider module both of them already depend on

Paths below are relative to the repo named in each citation. There was no
existing convention for research notes under `docs/`, so this file starts
`docs/research/`.

## TL;DR

- dnscli has no provider interface of its own. It drives the
  `dnsprovider.Provider` interface from `github.com/dnsgateway/dnsprovider`,
  and picks Providers from a `dnsprovider.Registry` keyed by type name
  (`dnscli/cmd/dnscli/main.go:31-33`, `dnscli/internal/provider/doc.go:1-5`).
  Adding dnsgate means writing **one `dnsprovider` adapter**: a type that
  implements `dnsprovider.Provider`, plus a `dnsprovider.Factory` that dnscli
  registers under `"dnsgate"`.
- The Gateway already uses `dnsprovider` *behind* its API: it builds a
  `dnsprovider.Provider` from the Provider Credential in each Service Token
  and calls it (`dnsgate/internal/gateway/dnscall.go:153-180`). Its record
  values and Zone states pass through unchanged. So the mapping is close to
  lossless for the fields both sides model.
- dnsgate does **not** speak any existing Provider's REST API. It speaks its
  own gRPC API (`GatewayService.Call`, one bidirectional stream per request,
  `dnsgate/api/dnsgate/v1/gateway.proto:13-28`). No existing dnsprovider
  adapter can be pointed at it with `WithBaseURL`.
- **Recommended:** put the adapter in the dnsgate repo as a public package,
  for example `github.com/dnsgateway/dnsgate/dnsprovider`. It can reuse
  `internal/client`, because Go allows packages inside the same module tree to
  import it. It would expose `Factory()`. dnscli then adds one line,
  `registry["dnsgate"] = gatewayprovider.Factory()`, as the `fakeprovider`
  build already does for its fake (`dnscli/cmd/dnscli/providers_fake.go:13-21`).
- Main gaps: the API is RRset-based and dnscli is record-based. Writes have no
  precondition, so there is a read-then-write race. The API exposes no TTL
  range or automatic-TTL information. Extras (Cloudflare `proxied`) are
  dropped. The optional Zone operations (create/delete/status/tenants) are
  missing. dnscli's account form treats every field as required. dnsgate
  declares `go 1.27`, while dnscli declares `go 1.24.0`.

## Decisions (2026-10-09)

Settled after the first pass; they override the matching items below.

- **Go version.** dnscli moves to `go 1.27` anyway, so requiring
  `github.com/dnsgateway/dnsgate` costs no extra toolchain bump. Splitting
  `api/` into its own module is no longer needed for this reason (open
  question 2 closed). The dependency raises (grpc, `modernc.org/sqlite`)
  remain and are accepted.
- **Egress is an Account setting.** The Factory gets an `egress` field
  (`auto` | `gateway` | `agent`, mapping to `EGRESS_UNSPECIFIED`,
  `EGRESS_GATEWAY`, `EGRESS_AGENT`, `api/dnsgate/v1/gateway.proto:270-280`).
  dnscli's form refuses empty fields (`dnscli/internal/tui/account.go:509-519`),
  so this needs either an `Optional bool` (or `Default string`) on
  `dnsprovider.Field` (`dnsprovider/config.go:66-77`) with the form honouring
  it, or a required field the user fills with `auto`. A `Choices []string`
  on `Field` would let the form offer a picker instead of free text. The
  first option is cleaner and also serves an optional CA field.
- **TTL range from the token's Provider.** The token itself is a JWE
  encrypted to the Gateway (`internal/token/claims.go:1-6`), so the client
  cannot read its body. But `InspectToken` returns the `provider` claim
  (`api/dnsgate/v1/gateway.proto:193-194`, `internal/token/claims.go:36-37`).
  The adapter calls it once (it already does for `Account()`) and implements
  `dnsprovider.TTLLimits` and `AutoTTL` (`dnsprovider/provider.go:158-188`)
  from that Provider type. `TTLRangeOf` needs a Provider value, not a type
  name, so either dnsprovider exposes the range per type (for example a
  `TTLRange` on `Factory`, or `TTLRangeOf` on a zero-value adapter), or the
  adapter keeps a table copied from `dnsprovider/docs/provider.md:104-115`.
  The dnsprovider-side lookup avoids the copy drifting. No API change needed
  in dnsgate (open question 5 closed).
- **Record extras are supported generally, `proxied` first.** dnsgate may
  change as needed to carry Provider-specific record parameters. Changing
  them needs plain `update`/`patch`. See §3a.

## Decisions (2026-10-10)

Settled in a second pass; they override the matching items below and the
2026-10-09 decisions where they differ.

- **Name and place.** The adapter is the **Gateway Adapter** (`GLOSSARY.md`).
  It lives in `github.com/dnsgateway/dnsgate/gatewayadapter` and exports only
  `Factory`, `New`, `Config` and the field names (ADR 0008).
- **Whole-RRset writes.** The Gateway Adapter's `ApplyChangeset` groups the
  changes by RRset and writes each RRset's target with `create`, `update` or
  `delete`; it never uses `patch`. RRsets that end empty go first, then the
  changed ones, then the new ones (`dnsprovider.ApplyOrder` at RRset level).
  It stops at the first failure.
- **Expected RRset.** `UpdateRecord` and `DeleteRecord` take an optional
  `ExpectedRRset{ttl, records}`. The Gateway compares it with the current
  RRset inside its read-then-apply (values as a set, TTL, and Record Extras
  under dnsprovider's equality rule) and refuses with `CONFLICT`. `create`
  already refuses an existing RRset; `patch` takes no Expected RRset. The
  dnsgate CLI does not expose it.
- **One TTL per RRset.** Accepted: every Record of an RRset carries the
  RRset's TTL, and a write sets it on all of them.
- **Account.** `Account()` calls `InspectToken`, and also `ListZones` when the
  token's Permissions grant `list` on `zones`. It returns
  `Tenant{ID: jti, Name: sub}`. Bound Tokens fail with a clear error until
  `internal/client` sends Identity Tokens.
- **TTL range and Record Extras metadata on `Factory`.** dnsprovider gains a
  per-type TTL range and automatic TTL, and `Extras []ExtraSpec`, on `Factory`
  (`ProxyFlag` becomes one entry). The Gateway's TTL check uses the same
  source, and it rejects unknown or read-only Record Extras with
  `INVALID_RECORD`.
- **Wire shape.** `repeated RecordValue records` replaces `values` in
  `RecordSet` and the write requests (the API is unreleased). `patch remove`
  stays value strings.
- **Record Extras merge per key.** A key sent sets that Record Extra, a key
  sent as `""` clears it, a key not sent keeps its current value; a new value
  starts with the keys it was sent. `plan()` treats an extras-only change as
  a modify.
- **Optional fields.** `dnsprovider.Field` gains `Default` (a field with a
  default is optional) and `Choices` (the form offers a picker). Egress is
  `{Default: "auto", Choices: [auto, gateway, agent]}`.
- **CA trust per process.** No CA field on the Account. dnscli takes a
  repeatable `--ca-file` (env `DNSCLI_CA_FILE`, a path list), adds them to
  the system roots, and registers `gatewayadapter.Factory(WithRootCAs(pool))`.
  `dnsgate --ca-file` becomes repeatable and keeps replacing the system roots.
- **Connections.** One `*grpc.ClientConn` per Gateway address, kept for the
  life of the process.
- **Partial view.** No flag in v1; a follow-up.
- **TXT help.** The dnsgate CLI help was wrong (TXT values are unquoted
  text); fixed. The `record` commands will be removed once dnscli manages
  records through the Gateway Adapter.

## 1. dnscli's provider architecture

### 1.1 The interface a Provider implements

dnscli's own `internal/provider` package is only "a thin layer over the
dnsprovider module (ADR-0006)". It reads credentials, opens Providers from
the Registry, and converts types (`dnscli/internal/provider/doc.go:1-5`).
(`ADR-0006` is cited there, but `dnscli/docs/adr/` holds only 0001–0005. The
nearest is `0003-own-provider-module.md:3`: "Providers live in a dnscli-owned
module behind a Changeset-based Provider interface". That module has since
become `github.com/dnsgateway/dnsprovider`.)

The required interface is `dnsprovider.Provider` (`dnsprovider/provider.go:5-33`):

```go
type Provider interface {
    Account(ctx context.Context) (AccountInfo, error)                                   // provider.go:9
    Zones(ctx context.Context, f ZoneFilter) ([]Zone, error)                            // provider.go:14
    Zone(ctx context.Context, name string) (Zone, error)                                // provider.go:17
    Records(ctx context.Context, zone Zone, f RecordFilter) (RecordSet, error)          // provider.go:20
    CreateRecord(ctx context.Context, zone Zone, r Record) (Record, error)              // provider.go:24
    UpdateRecord(ctx context.Context, zone Zone, before, after Record) (Record, error)  // provider.go:29
    DeleteRecord(ctx context.Context, zone Zone, r Record) error                        // provider.go:32
}
```

The contract notes that matter for a dnsgate adapter:

- `Account` "proves its credentials work, even when it has no Zones:
  ErrUnauthorized when they do not" (`provider.go:7-9`).
- `Zones`/`Records` must be **exactly filtered**. Adapters push filters down
  where they can and apply `MatchZone`/`MatchRecord` locally
  (`dnsprovider/docs/provider.md:195-199`, `dnsprovider/filter.go:20,38`).
- `Zone(name)` returns `ErrNotFound` when absent (`provider.go:15-17`).
- `CreateRecord` returns `ErrConflict` when an identical Record exists
  (`provider.go:21-24`).
- A Provider without record IDs finds `before` by content and fails with
  `ErrNotFound` when it is gone (`provider.go:25-29`).

Optional interfaces, detected by type assertion (`dnsprovider/provider.go:35-211`):
`Batcher` (`ApplyChangeset`), `ZoneStatusReader`, `ZoneCreator`, `ZoneUpdater`,
`ZoneDeleter`, `TenantLister`, `TTLLimits`, `AutoTTL`, `ProxyFlag`.

Construction goes through `Factory` (`dnsprovider/config.go:79-91`):

```go
type Factory struct {
    Fields       []Field
    New          func(fields map[string]string, opts ...Option) (Provider, error) // no network call
    Capabilities []Capability
}
type Field struct { Name, Label string; Secret, Tenant bool }  // config.go:66-77
type Registry map[string]Factory                                 // config.go:113
```

`New` must build "without a network call", and must reject a missing required
field or an unknown field (`config.go:83-85`). Options are `WithHTTPClient`,
`WithBaseURL` and `WithLogger` (`config.go:30-45`).

### 1.2 Registration and selection

- dnscli's registry is `var registry = providers.Registry()`
  (`dnscli/cmd/dnscli/main.go:31-33`). `providers.Registry()` returns one
  Factory per adapter in the module (`dnsprovider/providers/registry.go:24-39`).
- The map can be extended at init: the `fakeprovider` build tag adds
  `registry["fake"] = f.Factory()` (`dnscli/cmd/dnscli/providers_fake.go:1-21`).
- The registry is handed to the TUI as `Deps.Providers`
  (`dnscli/cmd/dnscli/main.go:166-174`). The TUI wraps it in
  `provider.NewOpener(deps.Providers)` with **no Options**
  (`dnscli/internal/tui/model.go:166`).
- `Opener.build` looks up the Factory by type and calls `f.New(fields, opts...)`
  (`dnscli/internal/provider/open.go:70-80,232-239`). `Opener.Verify` calls
  `p.Account(ctx)` before an Account is saved (`open.go:250-274`).

### 1.3 Config and credentials

- dnscli has no per-provider flags or env vars. Credentials come from the TUI
  account form, which builds one input per `Factory.Fields` entry that is not
  a Tenant field (`dnscli/internal/tui/account.go:97-112`). Secret fields are
  masked (`account.go:1197`).
- **Every credential field is required by the form**:
  `complete()` refuses any empty field (`dnscli/internal/tui/account.go:509-519`).
  `dnsprovider.Field` has no "optional" flag (`dnsprovider/config.go:66-77`).
- The field map is sealed as JSON (`dnscli/internal/provider/credentials.go:32-39`)
  inside SQLite, encrypted with a data key wrapped by Unseal Methods
  (`dnscli/docs/adr/0005-accounts-encrypted-in-sqlite.md:3`).
- Tenants: a field marked `Tenant` is filled by the Opener from
  `TenantLister.Tenants` (`dnscli/internal/provider/open.go:96-123,221-229`).

### 1.4 Record model

dnscli's cache types convert one-to-one to and from the module's types
(`dnscli/internal/provider/convert.go:12-90`):

- `dnsprovider.Zone{ID, Name, State, Nameservers}` (`dnsprovider/types.go:20-28`)
- `dnsprovider.Record{ID, Type, Name (absolute, no trailing dot), Value
  (presentation form), TTL, Extras}` (`dnsprovider/types.go:30-44`)
- Changesets go through `dnsprovider.Apply` (`dnscli/internal/tui/apply.go:290`).
  It first re-reads and compares the Before Records (stale check), then uses
  the `Batcher` if there is one. Otherwise it runs deletes, then modifies, then
  adds (`dnsprovider/apply.go:25-48`, `dnsprovider/docs/provider.md:299-323`).
- When the Provider reports no SOA serial (`RecordSet.Serial == 0`), dnscli
  falls back to the resolver's answer (`dnscli/internal/tui/refresh.go:311-312`).

### 1.5 Closest template

**Gandi** (`dnsprovider/providers/gandi/`) is the best template. Its API is
RRset-based (`rrset_name`, `rrset_type`, `rrset_ttl`, `rrset_values`,
`gandi/gandi.go:212-219`). It gives each Record a content-derived ID
(`gandi/gandi.go:230-233`). Its CRUD methods are one-change Changesets
through its `Batcher` (`gandi/write.go:23-33`). Its `ApplyChangeset` "plans the
complete final state before any write. Every RRset is replaced at most once"
(`gandi/write.go:61-64`). This is the same shape a dnsgate adapter needs.
GoDaddy also "writes whole RRsets" (`dnsprovider/docs/provider.md:348-354`),
but it is 900 lines (`providers/godaddy/godaddy.go`).

Caveat: Gandi uses `dnsprovider/internal/batch`, `internal/fields` and
`internal/names` (`gandi/write.go:14-16`, `gandi/gandi.go:60-63`). Those
packages are `internal` to the dnsprovider module, so an adapter **outside**
that module cannot import them
(Go "Internal Directories": <https://pkg.go.dev/cmd/go#hdr-Internal_Directories>).
They are small to copy: `batch` is ~40 lines (`internal/batch/batch.go`) and
`fields.Factory`/`Check` ~50 (`internal/fields/fields.go`). The public helpers
`QualifyName`, `RelativeName`, `MatchZone`, `MatchRecord`, `Editable`,
`CheckValue`, `SameRecord` and `ApplyOrder` are exported
(`dnsprovider/record.go:28,71,108,127,244`, `filter.go:20,38`, `apply.go:54`).

## 2. dnsgate's client API

### 2.1 What dnsgate is

"A security layer between applications and DNS provider APIs. It lets each
application manage only the DNS records it is permitted to, without ever
handing it the provider's credential" (`GLOSSARY.md:3`). The **Gateway**
"authorizes DNS requests and executes them against DNS providers on a client's
behalf" (`GLOSSARY.md:9-11`). The README lists "people who manage DNS records"
as an audience (`README.md:29`), and "Adapters: external-dns webhook provider,
Terraform" are under "Later" (`docs/draft.md:515`).

dnsgate is a gateway in front of other Providers, but it does **not**
impersonate their APIs. Clients speak dnsgate's own gRPC API
(`docs/draft.md:278`). The Gateway then calls the Provider through
`dnsprovider` (`internal/gateway/dnscall.go:163-177`). v1 supports Cloudflare
alone (`internal/provider/registry.go:24-31`). The one compatibility surface
planned is the ACME Endpoint (the acme-dns HTTPS API, a separate binary, TXT
`patch` only; `docs/adr/0003-acme-endpoint.md:3`). It is useless for a
general zone editor, and the code does not implement it yet: only a claim
comment mentions it (`internal/token/claims.go:22`).

### 2.2 Transport and operations

- One RPC: `rpc Call(stream CallRequest) returns (stream CallResponse)`
  (`api/dnsgate/v1/gateway.proto:27`). The client sends one `Request`. The
  Gateway answers with one `Response`, or ends the stream with a status that
  carries an `Error` detail (`gateway.proto:14-26`).
- `Request` is a oneof of 13 operations (`gateway.proto:106-122`). Those that
  matter to dnscli:

| Operation | Request fields | Result | Verb/resource needed |
| --- | --- | --- | --- |
| `InspectToken` | `token` | `sub, jti, ancestors, iat, nbf, exp, provider, permissions` | none beyond a valid, unrevoked token (`internal/gateway/inspect.go:11-15`) |
| `ListZones` | `token, egress` | `zones[]` (filtered to the token's zones) | `list` on `zones` (`gateway.proto:282-294`, `internal/gateway/zones.go:15-38`) |
| `GetZone` | `token, egress, zone` | `zone` | `get` on `zones` (`gateway.proto:296-308`) |
| `ListRecords` | `token, egress, zone` | `record_sets[]` (filtered per RRset) | `list` on `records` (`gateway.proto:332-346`, `internal/gateway/records.go:19-41`) |
| `GetRecord` | `token, egress, zone, name, type` | `record_set` | `get` (`gateway.proto:348-366`) |
| `CreateRecord` | `…, ttl, values[]` | `record_set`; fails if the RRset exists | `create` (`gateway.proto:368-393`, `internal/gateway/mutations.go:39-54`) |
| `UpdateRecord` | `…, ttl, values[]` | `record_set`; fails if the RRset is absent | `update` (`gateway.proto:395-421`, `mutations.go:59-74`) |
| `PatchRecord` | `…, ttl?, add[], remove[]` | `record_set` (omitted when emptied) | `patch` (`gateway.proto:423-455`, `mutations.go:118-170`) |
| `DeleteRecord` | `…, name, type` | empty | `delete` (`gateway.proto:457-474`, `mutations.go:174-196`) |

- Data model: `Zone{name, state (ACTIVE/PENDING/MOVED), nameservers}`, with
  **no zone ID** (`gateway.proto:310-330`). `RecordSet{name (relative, "@"
  for apex), type (upper case), ttl ("the lowest of its records'"), values[]}`,
  with **no record IDs** (`gateway.proto:476-487`).
- No pagination: `ListZones` and `ListRecords` return everything
  (`gateway.proto:290-294,342-346`). The Gateway pages through the Provider
  itself via `dnsprovider` (`internal/gateway/zones.go:22`, `records.go:70-82`).
- Every write is one `dnsprovider.Changeset` built by `plan()` with "as few
  changes as it can", and it prefers modify over delete+add so an RRset never
  goes empty (`internal/gateway/mutations.go:16-18,300-418`).
- There is no write precondition (an expected current value or version) on
  any write request (`gateway.proto:368-474`). The Gateway's own Changeset
  has a stale check only because `dnsprovider.Apply` re-reads what the Gateway
  read a moment earlier (`mutations.go:310`).
- Writes accept only `dnsprovider.Editable` types (A, AAAA, CNAME, MX, TXT,
  NS, SRV, CAA, URI) and check each value with `dnsprovider.CheckValue`
  (`internal/gateway/mutations.go:228-248`, `dnsprovider/record.go:25`). TTLs
  are checked against `dnsprovider.TTLRangeOf(provider)` on the server
  (`mutations.go:251-257`).

### 2.3 Auth model

- Each request carries the **Service Token** in its body (`token` field on
  every request message, for example `gateway.proto:284-287`). The token is
  self-contained: `JWE(JWS(claims))`, carrying the Provider Credential and the
  Permissions. The Gateway stores no credentials or policies
  (`docs/adr/0001-self-contained-service-tokens.md:3`).
- **Root Token** comes from Onboarding with the Bootstrap Secret. **Derived
  Tokens** come from `CreateToken`, under the **Narrowing** rule
  (`GLOSSARY.md:49-75`, `gateway.proto:198-215`).
- **Permission** = verbs (`get, list, create, update, patch, delete`) ×
  resources (`zones, records, tokens`; default `records`), with zone, name,
  type and egress filters. They only add up, and there is no deny
  (`internal/permission/permission.go:23-45`, `gateway.proto:489-499`,
  `GLOSSARY.md:69-71`).
- **Revocation** of a token revokes its descendants. It is checked on every
  request before Permissions (`internal/gateway/dnscall.go:103-120`,
  `docs/adr/0007-revocation-store-and-its-expiry.md:7`).
- **Bound Tokens** need an Identity Token, which "travels in gRPC stream
  metadata" (`docs/draft.md:506`, `docs/adr/0004-identity-binding-in-service-tokens.md:3`).
  `internal/client` does not send one today (no `metadata` or identity code in
  `internal/client/`). Unbound tokens stay usable by "people at a terminal"
  (ADR 0004, Considered Options).
- Errors: gRPC status plus `Error{category, dimension, provider_status}`
  (`gateway.proto:501-537`). Provider errors are mapped in
  `internal/gateway/errors.go:69-96`. A token that lacks a Permission gets
  `PERMISSION_DENIED`. A token whose list result is filtered gets **no
  error**: the out-of-scope zones and RRsets are just left out
  (`zones.go:29-35`, `records.go:31-36`).
- TLS: the CLI dials with TLS 1.3 minimum, and `--ca-file` or system roots
  (`cmd/dnsgate/client.go:22-48`). TLS must terminate at the Gateway
  (`docs/adr/0005-onboarding-relies-on-tls.md:13`).

### 2.4 Egress

`egress` is optional on every DNS request. Left unspecified, the Gateway uses
Gateway Egress if the token allows it, else Agent Egress
(`gateway.proto:270-280`, `internal/gateway/dnscall.go:122-145`). With Agent
Egress the client relays the Gateway's TLS bytes to the Provider inside the
same stream (`docs/adr/0006-agent-egress-relay-framing.md:3`).
`internal/client.New` always acts as Egress Agent, with default resolver and
dialer (`internal/client/client.go:22-32`, `internal/client/agent.go:36-57`).
So dnscli on a laptop could reach an IP-allowlisted Provider from the user's
own IP with no extra code. That is a real feature for dnscli users.

### 2.5 Reusable Go client

- `api/dnsgate/v1` (generated protobuf/gRPC, plus `ErrorDetail` and
  `Category.Name`) is a **public** package
  (`api/dnsgate/v1/gateway.proto:9`, `api/dnsgate/v1/errors.go:9-24`).
- `internal/client` is a complete typed client: one method per operation,
  stream handling, relay, and an `*Error` with `Detail()`
  (`internal/client/client.go:34-185`, `internal/client/errors.go:11-44`). It
  is **`internal`**, so only packages under `github.com/dnsgateway/dnsgate/`
  can import it.

## 3. Mapping dnscli/dnsprovider ↔ dnsgate

| dnsprovider | dnsgate | Adapter work / gap |
| --- | --- | --- |
| `Account()` | `InspectToken` | Valid token → `AccountInfo{Tenant{ID: jti, Name: sub}}`. Unauthenticated → `ErrUnauthorized`. No nameservers at account level (they are per-Zone, `gateway.proto:327-329`). Note: InspectToken proves the token opens, not that the Provider Credential still works. A `ListZones` call would prove that, but needs `list zones`. |
| `Zones(f)` | `ListZones` | `ID = Name` (no zone IDs). Map states 1:1 (`internal/gateway/zones.go:58-62`). Apply `MatchZone` locally. The list is the token's subset. |
| `Zone(name)` | `GetZone` | `NOT_FOUND` → `ErrNotFound`. |
| `Records(z, f)` | `ListRecords` | Expand each RRset into one Record per value. Name = `QualifyName(zone, name)`. TTL = RRset TTL. ID = content key (type, name, value), as Gandi does. Apply `MatchRecord` locally (no server-side filter). `Serial = 0` (none in the API); dnscli falls back to its resolver (`refresh.go:311`). |
| `CreateRecord(r)` | `PatchRecord{add:[v], ttl}` | Patch creates the RRset when absent and leaves others' values alone (`gateway.proto:423-428`). But "adding a value the RRset holds … change[s] nothing", so the adapter cannot detect the identical-Record `ErrConflict` the contract asks for without a `GetRecord` first. Needs `patch`. |
| `UpdateRecord(b, a)` same name+type, value change | `PatchRecord{add:[a.v], remove:[b.v], ttl}` | One call. The Gateway's `plan()` turns it into one modify. |
| `UpdateRecord` TTL-only | `UpdateRecord` with the full value list | Patch cannot change the TTL of a held value. The adapter must `GetRecord`, then `UpdateRecord` with every value. Mixed TTLs collapse to one (the RRset TTL is the min, `records.go:112`). |
| `UpdateRecord` name/type change | patch-remove at old + patch-add at new | Two calls, not atomic. Same as Gandi's cross-RRset move (`gandi/write.go:61-64`). |
| `DeleteRecord(r)` | `PatchRecord{remove:[v]}` | Removing the last value deletes the RRset (`gateway.proto:428`). |
| `Batcher.ApplyChangeset` | one `UpdateRecord`/`CreateRecord`/`DeleteRecord` per touched RRset | Group by (name, type), compute each RRset's target from a fresh `GetRecord`, then send one call per RRset. That is one Gateway Changeset per RRset; there is no cross-RRset atomicity. |
| `Extras` (`proxied`, comments, …) | `RecordValue.extras` (to add) | Dropped today on read (`records.go:107`) and never sent (`mutations.go:262-273`). Decided: carry per value, see §3a. |
| `TTLLimits`, `AutoTTL` | `InspectToken.provider` | Decided: derive from the token's Provider type (see Decisions). The Gateway still enforces the range (`mutations.go:251-257`). |
| `ZoneCreator/Updater/Deleter`, `ZoneStatusReader`, `TenantLister` | — | No such operations (`gateway.proto:106-122`). Leave unimplemented; dnscli checks with the `Can*` helpers (`dnsprovider/provider.go:82-153`). |
| Errors | `Error.category` | `UNAUTHENTICATED`, `PERMISSION_DENIED`, `DENIED_BY_PROVIDER` → `ErrUnauthorized`; `NOT_FOUND` → `ErrNotFound`; `RATE_LIMITED` → `ErrRateLimited`; `CONFLICT` → `ErrConflict`; `INVALID_RECORD`/`INVALID_REQUEST` → `*APIError{StatusCode: 400}`; others → `*APIError` with `provider_status` (`gateway.proto:501-537`, `dnsprovider/errors.go:11-106`). Carry the Gateway message in `APIError.Messages`; it never quotes secrets (`internal/gateway/errors.go:16`). |
| Values | values | Same presentation form both ways. The Gateway passes `dnsprovider.Record.Value` through untouched (`records.go:113`, `mutations.go:262-273`), so no conversion is needed. (One inconsistency: the dnsgate CLI help says TXT is `'"text"'`, `cmd/dnsgate/record.go:18`, while dnsprovider documents TXT as "any non-empty text", `dnsprovider/record.go:20`. Worth checking, but the adapter is unaffected.) |
| Names | relative, `@` | `dnsprovider.QualifyName` / `RelativeName` (`dnsprovider/record.go:71-123`). The Gateway lower-cases names (`internal/dnsname/dnsname.go:12-35`). |

Permission behaviour dnscli users will notice:

- A token scoped to a few names shows a **partial zone**: the out-of-scope
  RRsets are silently absent (`records.go:31-36`). dnscli's "Zone Status"
  (MX/SPF heuristics) and Delegation display then see only that subset.
- dnsprovider's stale check re-reads with a `RecordFilter` by type and name
  (`dnsprovider/docs/provider.md:304-306`). With a scoped token this still
  works, because the re-read covers the same RRsets.
- A token without `patch` cannot use the patch-based single-record path. The
  adapter could fall back to `create`/`update`/`delete` on whole RRsets, or
  require `patch`. A sensible minimum token for dnscli is
  `verbs: [get, list, create, update, patch, delete]` on `zones` and `records`.

## 3a. Record extras through the Gateway (Cloudflare `proxied` first)

Decided: dnsgate gains general support for Provider-specific record
parameters (dnsprovider's `Record.Extras`), not a one-off `proxied` field.
Changing an extra needs the same permission as changing the record:
`update`, or `patch`, under the usual zone, name and type filters. No
separate permission or filter.

### What dnsprovider has today

`Record.Extras map[string]string` holds Provider-specific fields; each
provider package exports its keys (`dnsprovider/types.go:41-43`). The ones
in the tree:

| Provider | Key | Written? | Scope |
| --- | --- | --- | --- |
| Cloudflare | `proxied` (`dnsprovider.ExtraProxied`) | yes (`providers/cloudflare/cloudflare.go:943`) | per record, A/AAAA/CNAME only (`provider.go:190-193`) |
| Cloudflare | `comment`, `tags` | no, "a write keeps the comment Cloudflare holds" (`cloudflare/cloudflare.go:573-581`) | per record |
| Porkbun | `notes` | yes (`providers/porkbun/write.go:53`) | per record |
| Hetzner | `comment` | no, a write keeps the existing comment (`providers/hetzner/write.go:232`) | per value (`hetzner.go:28-29`) |
| Hetzner | `labels`, `protected` | no, read-only (`hetzner.go:30-33`) | per RRset |
| DNSimple | `regions`, `system_record`, `parent_id` | no, read-only (`providers/dnsimple/read.go:229-234`) | per record |
| Internet.bs | `internetbs:wire_value` | used to match the record on write (`providers/internetbs/write.go:62-83`) | per record |

Two consequences:

- Extras are **per record**, so the API needs per-value extras, not one map
  per RRset. That also settles the "mixed `proxied` in one RRset" question:
  each value carries its own flag, whatever Cloudflare allows.
- dnsprovider has **no machine-readable list of which keys a Provider takes
  on write**; it is only in doc comments. Providers ignore read-only keys on
  write, so passing them through is harmless, but the Gateway cannot reject
  an unknown or read-only key with a clear error, and cannot tell dnscli which
  extras to offer for editing. Proposed dnsprovider addition: an optional
  interface or `Factory` field such as
  `Extras []ExtraSpec{Key, Label string; Writable bool; Types []string; Kind (bool|string|json)}`.
  `ProxyFlag` (`provider.go:195-210`) becomes one instance of it.

### Changes in dnsgate

1. **Wire** (`api/dnsgate/v1/gateway.proto:477-487`). Add a per-value form
   next to `values`, for example:

   ```proto
   message RecordValue {
     string value = 1;
     map<string, string> extras = 2;
   }
   message RecordSet {
     ...
     repeated string values = 4;        // kept: values only
     repeated RecordValue records = 5;  // values with their extras
   }
   ```

   The write requests (`CreateRecord`, `UpdateRecord`, `PatchRecord` add)
   take `RecordValue` the same way. A client that only sends `values` keeps
   today's behaviour, and an existing record's extras are kept (see 3).
2. **Read** (`internal/gateway/records.go:95-113`). Fill `records` with each
   value's `rec.Extras`.
3. **Write** (`internal/gateway/mutations.go:262-273`, `records()`). Copy the
   request's extras into `dnsprovider.Record.Extras`. When a value comes
   without extras and the record already exists, keep its current extras
   rather than clearing them (the modify path already copies `current[i]`,
   `mutations.go:391`). If the `ExtraSpec` list exists, reject unknown or
   read-only keys with `INVALID_RECORD`.
4. **Change detection** (`plan()`, `mutations.go:359-394`). It matches by
   value and keeps a record whose TTL is unchanged, so an extras-only edit
   (such as switching `proxied`) is silently a no-op today. It must also
   compare extras, ideally with dnsprovider's own rule
   (`dnsprovider/stale.go:206-219`, which treats `proxied: false` as equal to
   absent).
5. **Audit.** Extras changes show up in the Changeset like any modify; check
   that the audit record carries them so that proxy toggles are visible.
6. **Permission.** Nothing new: extras ride on `update`/`patch` (decided).

### Adapter side

The adapter maps `Record.Extras` to and from `RecordValue.extras` one to
one, and implements `ProxyFlag` when `InspectToken.provider` is
`cloudflare`. dnsprovider's stale check already compares extras
(`dnsprovider/stale.go:206-219`), so dnscli's Apply check works unchanged.

## 4. Integration options

### A. Adapter package in the dnsgate repo (recommended)

A new public package, for example `github.com/dnsgateway/dnsgate/dnsprovider`
(or `…/provider/gateway`; the name `internal/provider` is taken). It
implements `dnsprovider.Provider` + `Batcher` over `internal/client`, and
exports `Factory()`. dnscli registers it:

```go
// dnscli/cmd/dnscli/main.go (or a providers_dnsgate.go init, like providers_fake.go)
registry["dnsgate"] = gatewayprovider.Factory()
```

- Pros: dnsgate owns its wire protocol and its adapter, so they change
  together. It reuses `internal/client` (relay, error unwrapping) without
  making it public API. No module cycle: dnsgate already depends on
  dnsprovider (`go.mod:6`), and the adapter only adds a consumer. The adapter
  can be tested in-repo against the real Gateway with a `providertest` fake
  Provider behind it.
- Cons: dnscli's `go.mod` must require `github.com/dnsgateway/dnsgate`. Its
  `go 1.27` (`dnsgate/go.mod:3`) forces dnscli's `go 1.24.0`
  (`dnscli/go.mod:3`) up, because a module's go line must be at least each
  dependency's (<https://go.dev/doc/toolchain>). MVS also raises shared
  requirements such as `modernc.org/sqlite` v1.46.1 → v1.60.1
  (`dnscli/go.mod:14`, `dnsgate/go.mod:13`) and pulls grpc/protobuf into the
  graph. dnsgate uses Go 1.26+ APIs such as `errors.AsType`
  (`internal/gateway/errors.go:101`), so lowering its go line is not free.

### B. Adapter in the dnsprovider repo (`providers/dnsgate`)

- Pros: it sits beside the other adapters, can use `internal/batch`,
  `internal/fields` and `internal/livetest`, and joins `providers.Registry()`
  automatically.
- Cons: dnsprovider would require dnsgate while dnsgate requires dnsprovider,
  a module-level require cycle. It would also need dnsgate to export its
  client (`internal/client` is not importable from another module). And
  `providers.Registry()` imports every adapter
  (`dnsprovider/providers/registry.go:6-20`), which would push gRPC and Go
  1.27 onto every dnsprovider consumer, the Gateway itself included. Not
  recommended now.

### C. Adapter inside dnscli (`dnscli/internal/provider/dnsgate`)

- It could use only the public `api/dnsgate/v1` and reimplement the stream
  round-trip (~50 lines, `internal/client/client.go:128-185`). Supporting
  Agent Egress would mean copying the ~320-line relay (`internal/client/agent.go`)
  or leaving Agent Egress unsupported.
- Cons: protocol knowledge would be duplicated outside the repo that owns it.
  It has the same go.mod/go-version cost as A, because it imports a dnsgate
  package.

### D. Reuse an existing adapter pointed at dnsgate

Not possible. dnsgate exposes no Provider-compatible REST API (§2.1), so
`WithBaseURL` on, say, the Cloudflare adapter has nothing to talk to. Making
dnsgate emulate Cloudflare's v4 API would contradict its own design: the
GLOSSARY tells writers to avoid calling the Gateway a "proxy"
(`GLOSSARY.md:11`), and the draft names gRPC as the client protocol
(`docs/draft.md:278`).

### Recommended outline (option A)

In dnsgate:

- `dnsprovider/doc.go`: package doc, glossary terms.
- `dnsprovider/config.go`:
  - `const FieldGateway = "gateway"` (host:port), `FieldToken = "token"`
    (Secret), `FieldEgress = "egress"` (`auto` | `gateway` | `agent`).
  - `type Config struct{ Gateway, Token string; RootCAs *x509.CertPool; Egress dnsgatev1.Egress }`
  - `func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error)`:
    `grpc.NewClient` is lazy, so the "no network call" rule
    (`dnsprovider/config.go:84`) holds.
  - `func Factory() dnsprovider.Factory`: fields `gateway` ("Gateway
    address"), `token` ("Service Token", Secret). Reject unknown fields as
    `internal/fields.Check` does (copy it). No `Capabilities`.
  - Map `dnsprovider.WithBaseURL` to the Gateway address for tests.
    `WithHTTPClient` does not apply to gRPC.
- `dnsprovider/read.go`: `Account` (InspectToken), `Zones`, `Zone`,
  `Records` (RRset → Records, content-key IDs, local `MatchRecord`).
- `dnsprovider/write.go`: `ApplyChangeset` grouped per RRset (Gandi's shape),
  and `CreateRecord`/`UpdateRecord`/`DeleteRecord` as one-change Changesets
  (copy of `internal/batch`).
- `dnsprovider/errors.go`: category → `dnsprovider` error mapping (§3).
- Tests: in-process Gateway (as `internal/gateway` tests already build one)
  with `providertest` behind it, plus a `dnsprovider/providertest`-style
  conformance pass.

In dnscli:

- `cmd/dnscli/main.go`: `registry["dnsgate"] = gatewayprovider.Factory()`.
- `go.mod`: require `github.com/dnsgateway/dnsgate`, add
  `replace … => ../dnsgate` for local development (as is already done for
  dnsprovider, `dnscli/go.mod:54`), and raise `go` to 1.27.
- Optionally `internal/provider/credentials.go`: nothing. A JSON field map
  just works (`credentials.go:18-30`).

## 5. Open questions and dnsgate-side changes

1. ~~**Where does the adapter live, and under what name?**~~ Closed: `gatewayadapter`, ADR 0008. Option A needs a new
   public package in dnsgate. Is the Gateway repo willing to carry a public
   Go API surface, given that it is otherwise all `internal/`?
2. ~~**Go version / dependency weight.**~~ Closed: dnscli moves to `go 1.27`
   anyway (see Decisions).
3. ~~**Optional credential fields.**~~ Closed: `Field.Default` and `Choices`; CA trust is per process. Egress is decided as an Account setting
   (see Decisions); what remains is how: an `Optional`/`Default` (and maybe
   `Choices`) on `dnsprovider.Field` plus dnscli form support
   (`account.go:509-519`), which also covers a CA file/PEM.
4. ~~**Write preconditions.**~~ Closed: the Expected RRset on `update` and `delete`. The API has no "expected current values" on
   `UpdateRecord`/`PatchRecord`/`DeleteRecord`. dnscli's Apply stale check
   (ADR 0001, `dnscli/docs/adr/0001-cache-first-with-write-gate.md:3`)
   therefore runs client-side, followed by a separate unconditional write.
   Adding an optional `expect` (prior values + TTL) to the mutation requests
   would let the Gateway refuse with `CONFLICT` inside its own read-then-apply (`mutations.go:300-357`).
5. ~~**TTL range / automatic TTL.**~~ Closed: derived from
   `InspectToken.provider` (see Decisions). Remaining choice: per-type lookup
   in dnsprovider, on `Factory` (decided 2026-10-10).
6. ~~**Record identity.**~~ Closed: one TTL per RRset, accepted. No record IDs, and the RRset TTL is the minimum
   (`records.go:112`). Records of one RRset with different TTLs cannot be
   edited individually through the API. Accept, or return per-value TTLs.
7. ~~**Account verification.**~~ Closed: `ListZones` too, when permitted. `InspectToken` does not touch the Provider. Should
   `Account()` also call `ListZones` (needs `list zones`) to prove the Provider
   Credential still works?
8. ~~**Visibility of filtering.**~~ Deferred to a follow-up. List responses silently drop out-of-scope
   zones and RRsets. A flag such as `partial: true` would let dnscli label the
   zone as a partial view instead of implying the rest does not exist.
9. **Optional Zone operations** (Onboard/Offboard zone, DNSSEC/HSTS status,
   Tenants) are absent from the API. That is fine for v1. dnscli hides them
   through the `Can*` checks.
10. ~~**Bound Tokens.**~~ Closed: unbound only until a follow-up. Identity Tokens in stream metadata are not in
    `internal/client` yet. dnscli would support unbound tokens only until then.
11. ~~**gRPC connection lifetime.**~~ Closed: one connection per address. `dnsprovider.Provider` has no `Close`, and
    dnscli's Opener keeps Providers per credentials (`open.go:24-28`). The
    adapter should share one `*grpc.ClientConn` per Gateway address
    (package-level) rather than leak one per `New`.
12. ~~**TXT value form.**~~ Closed: the CLI help was wrong, fixed. The dnsgate CLI help (`cmd/dnsgate/record.go:18`) and
    dnsprovider (`dnsprovider/record.go:20`) describe TXT differently. Confirm
    which one the Gateway expects before dnscli users edit TXT through it.
