# DNS Gateway — Architecture

## Goal

Many DNS providers issue only one API credential, or a very broad account-level one. Applications such as `external-dns`, `cert-manager`, CI/CD jobs, Terraform, internal tools and people should not receive that raw credential.

The **Gateway** sits between clients and DNS provider APIs and enforces fine-grained permissions. Goals:

- Clients never see the raw Provider Credential.
- The Gateway never stores Provider Credentials, in its database or anywhere else.
- Clients get independently revocable tokens with fine-grained DNS permissions.
- Revoking a token never requires rotating the Provider Credential.
- Providers that restrict API access by source IP are supported.
- A request can leave either from the Gateway or from the client's network.
- Authorization and audit stay centralized in the Gateway.

Terms are defined in [GLOSSARY.md](../GLOSSARY.md). Key decisions are in [ADR 0001](adr/0001-self-contained-service-tokens.md) (self-contained tokens) [ADR 0002](adr/0002-gateway-names-agent-egress-destination.md) (Agent Egress destinations) and [ADR 0004](adr/0004-identity-binding-in-service-tokens.md) (workload identity). Sequence diagrams are in [flows.md](flows.md).

---

# Main Principle

Keep three things separate:

```text
Service Token        → what a client may request
Provider Credential  → how the Gateway authenticates to the Provider
Egress               → where the TCP connection to the Provider leaves from
```

The client may choose its Egress. The Gateway is always the final authority on what is allowed.

---

# Actors

## Administrator

A person who onboards Provider Credentials into the Gateway and holds tokens that may issue other tokens. The Administrator:

- onboards a Provider Credential, which produces a Root Token;
- issues Derived Tokens with narrower Permissions;
- revokes tokens;
- reseals tokens after the Gateway's key is rotated.

Onboarding requires a **bootstrap secret** configured on the Gateway. Every other administrative action is authorized by the permissions inside the token presented. There are no separate administrator accounts.

## Service Account

The name of the application or workload a token was issued for, for example:

```text
external-dns-prod
cert-manager-prod
terraform-dns
github-actions-release
```

A Service Account is a **label** carried in the token's `sub` claim, not a record the Gateway keeps. It appears in audit events. One Service Account can hold several independently revocable tokens.

## Client

The process that presents a Service Token and sends DNS requests, such as the Gateway CLI. When a request uses Agent Egress, the client also acts as the **Egress Agent**: it relays the Gateway's TLS connection to the Provider over the same connection it used to send the request. There is no separate agent identity or agent daemon.

---

# Service Tokens

## Self-contained

A Service Token carries everything needed to authorize and execute requests: the Service Account, the Permissions and the encrypted Provider Credential. The Gateway stores no credentials, policies or token records (ADR 0001).

```text
Service Token = JWE( JWS( claims ) )

claims  → sign with the Gateway's signing key      (JWS, Ed25519)
        → encrypt with the Gateway's encryption key (JWE, ECDH-ES+A256KW / A256GCM)
```

- The signature provides authenticity and integrity.
- Encryption provides confidentiality: a client holding the token can't read the Provider Credential, the Permissions, the zones or the Service Account.
- Library: `go-jose` v4.

Only the Gateway can create or read Service Tokens. It holds both private keys.

## Keys

| Key | Purpose | `kid` location |
|---|---|---|
| Signing key (Ed25519) | sign claims | inner JWS header, e.g. `sig-2026-10` |
| Encryption key (X25519) | encrypt the signed token | outer JWE header, e.g. `enc-2026-10` |

In v1 both keys are PEM files the Gateway reads at startup, kept behind a key interface so KMS support can be added later. KMS would protect the keys at rest. It would not protect against a compromised running Gateway, because Provider Credentials are decrypted into Gateway memory either way.

The only readable part of a token is the outer header:

```json
{ "typ": "dnsgate+jwe", "alg": "ECDH-ES+A256KW", "enc": "A256GCM", "kid": "enc-2026-10" }
```

## Claims

The claim schema is fixed in [internal/token/claims.go](../internal/token/claims.go). The `credential` value and the IDs are shortened here.

```json
{
  "iss": "dnsgate",
  "aud": "dnsgate",
  "sub": "external-dns-prod",
  "jti": "tok_01JCHILD...",
  "iat": 1791417600,
  "nbf": 1791417600,
  "exp": 1799193600,
  "ancestors": ["tok_01JROOT..."],

  "provider": "cloudflare",
  "credential": { "type": "api-token", "value": "..." },

  "permissions": [
    {
      "verbs": ["get", "list", "create", "update", "patch", "delete"],
      "resources": ["records"],
      "zones": ["example.com"],
      "names": ["*.apps"],
      "types": ["A", "AAAA", "TXT"],
      "egress": ["agent"]
    }
  ]
}
```

Each token is bound to exactly one Provider and one Provider Credential, so requests do not name a provider.

From v2, a token may also carry an `identity` claim (an Identity Binding), which makes it a Bound Token usable only with a matching Identity Token. See [oidc.md](oidc.md).

## Onboarding and the Root Token

Onboarding is the only time the Provider Credential is handled in plaintext outside the Gateway:

```text
Administrator --(bootstrap secret, provider, Provider Credential)--> Gateway
Gateway: build claims → sign → encrypt → Root Token
```

The Provider Credential and the bootstrap secret are protected in transit by TLS alone, which must terminate at the Gateway ([ADR 0005](adr/0005-onboarding-relies-on-tls.md)).

A **Root Token** has full Permissions on everything the Provider Credential can reach (`zones: ["*"]`, `types: ["*"]`, `names: ["@", "**"]`, all verbs on `zones`, `records` and `tokens`, both egresses). By default it has **no expiry**. A CLI flag can set one.

## Derived Tokens and Narrowing

Presenting any token that holds `create` on `tokens` lets you issue a **Derived Token**. The presented token is its **Parent Token**. The Gateway decrypts the parent, checks it, and mints the new token. The Provider Credential is copied from the parent and never leaves the Gateway in plaintext.

**Narrowing**: a Derived Token never exceeds its Parent Token.

- Every Permission dimension (verbs, resources, zones, names, types, egress) must be covered by the Parent Token's Permissions. A filter left out of the Derived Token means "any", so it is accepted only if the parent's matching filter is "any" too. A Derived Token rule that leaves out `resources` means `["records"]`.
- A Derived Token can hold `create` on `tokens` only if its parent does.
- The Derived Token's `exp` can be no later than the parent's. Under a parent with no expiry it may also have none; under a parent with an expiry it must set one.
- Each combination of a Derived Token rule's verb, resource, egress, zone and type must be allowed by one parent rule. Its name patterns may be covered by the name patterns of all those parent rules together: `*` and `*.**` together cover `**`. Pattern containment is decided exactly.
- A refused Derived Token fails as a narrowing violation naming the dimension it exceeds, such as `zones` or `exp`.
- From v2, a Derived Token keeps its parent's Identity Binding and may only add claims to it ([oidc.md](oidc.md)).

Chains can go as deep as the Gateway's `tokens.maxAncestors` setting allows, eight Derived Tokens below the Root Token by default: a token with that many ancestors cannot issue tokens. Each token carries the IDs of all its ancestors in `ancestors`, root first. Issuing writes a `token.create` audit event naming the parent's `jti`, the new `jti` and the new token's Service Account.

## Revocation

The Gateway database stores **only revoked token IDs**. A token is rejected if its own `jti`, or any ID in its `ancestors`, has been revoked. Revoking a token therefore revokes every token derived from it. Revoking a Root Token disables everything issued under that onboarding.

Any token holding `delete` on `tokens` may revoke any token ID. With no token registry, the Gateway can't check which chain an ID belongs to (ADR 0001).

Entries for tokens with an expiry can be removed once that expiry passes. Entries for tokens without an expiry stay forever. The Gateway learns a token's expiry only from the token itself: `dnsgate token revoke` takes either a token ID or the full Service Token. Given the token, the Gateway opens it and keeps the entry until its `exp`. Given only an ID, it cannot know the expiry, so the entry stays forever (ADR 0007).

## Rotation

| What rotates | Effect |
|---|---|
| Gateway encryption key | New tokens use the new `kid`. Existing tokens are **resealed** (re-encrypted under the new `kid` with unchanged claims). Old decryption keys are kept by `kid` until a set retirement deadline. |
| Provider Credential | The Administrator's responsibility at the Provider. Afterwards, Onboard again and issue new Derived Tokens. |
| Permissions | Issue a new Derived Token and revoke the old one. |

The Gateway configuration names one current encryption key and any number of older decryption keys, each with a retirement deadline. From its deadline on, a decryption key opens no token, so a token not resealed by then stops working.

A token authorizes its own Resealing: `dnsgate token reseal` needs no Permission, because the resealed token carries the same claims and signature and grants its holder nothing new. A token that no longer opens (expired, tampered, or sealed under a retired key) cannot be resealed. Resealing writes a `token.reseal` audit event naming the old and new `kid`. Only the encryption key rotates this way; the signing key stays, so a resealed token keeps its signature.

---

# Permission Model

Permissions follow the **Kubernetes RBAC** style.

- **Verbs**: `get`, `list`, `create`, `update`, `patch`, `delete`
- **Resources**: `zones`, `records`, `tokens`
- **Filters**: `zones`, `names`, `types`, `egress`. A filter that is left out means "any": no `zones` equals `zones: ["*"]`, no `names` equals `["@", "**"]`, no `types` equals `["*"]`, and no `egress` equals `["gateway", "agent"]`.
- `resources` left out means `["records"]`, not "any". Access to `zones` and `tokens` must always be granted explicitly.
- `verbs` is required in every Permission entry. Leaving it out is an error.
- Rules **only add up** and there is no deny: a request is allowed if any Permission entry allows it.
- Narrowing works like Kubernetes escalation prevention: you can only grant what you already hold.

## Verbs on records

| Verb | Meaning |
|---|---|
| `get`, `list` | read records; results are filtered to what the token covers |
| `create` | create an RRset |
| `update` | replace an RRset (all records with the same name and type) |
| `patch` | add or remove single values inside an RRset (e.g. ACME TXT values) |
| `delete` | delete an RRset |

`patch` alone may also create and delete an RRset: adding a value to an RRset the zone lacks creates it, and removing its last value deletes it. An ACME client needs both, and holds only `patch`. A token limited to `patch` can therefore still create and empty RRsets within its zones, names and types; what it cannot do is replace or delete an RRset whole in one request.

On `tokens`, `create` issues a Derived Token and `delete` revokes a token.

## Name patterns

- Names are written **relative to the zone**. `@` is the zone's own name.
- `*` matches exactly one label.
- `**` matches one or more labels.
- Neither matches the empty name: `*.apps` does not match `apps`.

These rules are simple enough for the Gateway to decide whether one pattern contains another, which Narrowing requires.

## Examples

`external-dns`:

```yaml
permissions:
  - verbs: [get, list, create, update, patch, delete]
    resources: [records]
    zones: [example.com]
    names: ["**.apps"]
    types: [A, AAAA, CNAME, TXT]
    egress: [gateway, agent]
```

`cert-manager`:

```yaml
permissions:
  - verbs: [get, list, patch]
    resources: [records]
    zones: [example.com]
    names: ["_acme-challenge", "_acme-challenge.**"]
    types: [TXT]
    egress: [agent]
```

## Egress authorization

The client may request `egress=gateway` or `egress=agent`. The Gateway allows it only if a matching Permission entry includes that egress.

- If the token allows only one egress, that egress is used.
- If the token allows both and the request doesn't say which, the Gateway uses **Gateway Egress**.
- A token limited to `agent` can never fall back to `gateway`. A stolen token therefore reaches the Provider only from the thief's own IP, where the Provider's IP restriction rejects it.

## Possible future constraints

Not in v1: minimum and maximum TTL, maximum records per request, source CIDRs, record value restrictions, mutation rate limits, restrictions on other record attributes.

---

# Gateway State

| Data | v1 storage |
|---|---|
| Revoked token IDs | SQLite (PostgreSQL later) |
| Signing and encryption keys | PEM files |
| Bootstrap secret | Gateway configuration |
| Audit events | structured JSON logs |

Not stored anywhere: Provider Credentials, Permissions, Service Accounts, issued-token records.

v1 runs **a single Gateway instance**. Storage sits behind an interface so that replicas sharing PostgreSQL are possible later. Deployments that include the v2 ACME Endpoint **require PostgreSQL**, because it shares the revoked-ID list with the Gateway.

---

# API and Transport

Clients talk to the Gateway over **gRPC**, with **one bidirectional stream per request**. The only exception is the v2 ACME Endpoint, which speaks the acme-dns HTTPS API (see below). For Agent Egress, the relay to the Provider runs inside that same stream, so the relay always belongs to the connection that presented the token.

Conceptual request:

```json
{
  "token": "<Service Token>",
  "operation": "records.create",
  "egress": "agent",
  "zone": "example.com",
  "record": { "name": "www.apps", "type": "A", "value": "192.0.2.10", "ttl": 300 }
}
```

- A request never names a provider and never contains a Provider Credential.
- Responses are filtered: `list` returns only zones and records the token covers.
- Provider errors are mapped to Gateway errors that carry the Provider's HTTP status and a category (`denied by provider`, `not found`, `rate limited`, `invalid record`). The full Provider response, with credentials removed, goes only to the audit log.
- Amendment to spec #1: a mutation that collides with what the Provider holds fails with the category `conflict`: a `create` of an RRset the zone already holds (gRPC `AlreadyExists`), and a Changeset the Provider refuses because records changed underneath it or a record collides (gRPC `Aborted`). Retrying after reading the RRset again may succeed.

## Request execution order

The Provider Credential is used only after every check succeeds:

```text
receive request
  ↓
read JWE kid → decrypt
  ↓
read JWS kid → verify signature
  ↓
check iss / aud / nbf / exp
  ↓
check jti and ancestors against revoked IDs
  ↓
Bound Token (v2): verify the Identity Token and match the Identity Binding
  ↓
check Permissions: verb, resource, zone, name, type
  ↓
check egress
  ↓
open the Provider connection (Gateway Egress or Agent Egress)
  ↓
inject the Provider Credential, execute the Provider request
  ↓
map the response, discard the plaintext credential
  ↓
audit event
```

The Provider Credential must never appear in logs, traces, panic output, metric labels, audit data, error responses or debug dumps.

---

# Egress

## Gateway Egress

```text
Client ──gRPC──► Gateway ──HTTPS──► Provider
```

The Provider sees the Gateway's IP. Use it where source IP doesn't matter or the Gateway's IP is allowlisted.

## Agent Egress

Use it when the Provider Credential is restricted to the client's public IP.

```text
Gateway                 Client (Egress Agent)        Provider
   │  OPEN host:443 (on the request stream)               │
   │───────────────────────►│                             │
   │                        │ check, resolve, TCP connect │
   │                        │────────────────────────────►│
   │  TLS handshake and encrypted HTTP, relayed as bytes  │
   │◄──────────────────────►│◄───────────────────────────►│
```

- The Provider sees the **client's** IP.
- TLS runs end-to-end between the Gateway and the Provider. The client relays only ciphertext and never terminates TLS. The Provider Credential is visible only inside that TLS session.
- The Gateway verifies the Provider's certificate strictly.

In Go, the Provider HTTP client uses `http.Transport` with a custom `DialContext` that returns a `net.Conn` backed by the relay stream. TLS still runs inside `http.Transport` on the Gateway. The relay frames, half-close, flow control and timeouts are in [ADR 0006](adr/0006-agent-egress-relay-framing.md).

## Agent Egress destination rules

The Gateway sends a **full hostname and port** (ADR 0002). The client enforces:

- port **443** only;
- after resolving the hostname, refuse loopback, RFC1918, link-local, CGNAT, IPv6 ULA and `169.254.169.254`.

Known risk (accepted for v1): a compromised Gateway can make a client open TLS connections to any public host on port 443, from the client's IP. A client-side hostname allowlist can be added later.

---

# Providers

## v1: Cloudflare

- Credential type: **Cloudflare API token** (Bearer), which can be scoped to zones and restricted by IP.
- The zone name is resolved to a Cloudflare zone ID through the Cloudflare API.
- Cloudflare works on individual records. The adapter maps the RRset-level verbs (`create`, `update`, `delete`) and value-level `patch` onto per-record calls.

## Provider adapter structure

Networking is injected, so adapters never implement egress themselves:

```text
Provider Adapter (Cloudflare, …)
        │
        ▼
Provider HTTP Client
        │
        ▼
Egress Transport
   ├── Gateway Egress (direct dial)
   └── Agent Egress   (relay stream DialContext)
```

```go
type Provider interface {
    Zones(...)
    Records(...)
    CreateRecord(...)
    UpdateRecord(...)
    DeleteRecord(...)
}
```

---

# Audit Logging

Every mutation and every denied request produces one structured JSON log event.

Fields: timestamp, request ID, Service Account, token `jti`, provider, zone, record name, record type, verb, requested egress, actual egress, result, Provider response status, duration. For a Bound Token (v2), also the Identity Token's issuer and `sub` and the bound claim values.

Results: `ok`; `denied` for a request outside the token's Permissions or refused before they are checked (a token that does not open, a malformed zone, name or type); `failed` for a request the Permissions allowed that then failed, such as malformed record values or TTL, an RRset that already exists or is missing, or a Provider error. Every denial carries the verb, and the zone, record name and type that passed the Gateway's form checks, even when the token does not open; one that failed them may hold anything and is left out.

Mutation events also carry `changes_applied`, the number of changes of the Changeset the Provider confirmed. A Provider that confirms changes one at a time may make some and fail others: the request fails, the changes made stay, and `changes_applied` says how many there were.

An audit event of a zone or record request that cannot be written is logged as an operational error, naming the request ID and event. A denied or failed request is refused to the client either way. A mutation the Provider already made stays made and is answered as successful: the change cannot be withheld, so its only trace is then that operational log line.

Never logged: the Provider Credential, the Service Token itself, Identity Tokens, authorization headers, raw Provider HTTP headers.

---

# CLI

```text
dnsgate onboard --provider cloudflare [--expires DURATION]   # needs the bootstrap secret → Root Token
dnsgate token create --sub NAME --permissions FILE [--expires DURATION] [--bind-k8s|--bind-github|--bind-gitlab ...]   # binding: v2, see oidc.md
dnsgate token revoke TOKEN_ID|TOKEN|-                         # a token, or - for stdin, lets the entry be purged at its exp
dnsgate token reseal TOKEN
dnsgate token inspect                                        # the Gateway decrypts and shows permissions to the holder
dnsgate zone list|get ...
dnsgate record list|get|create|update|patch|delete ...
```

There are no `service-account` commands, because Service Accounts are labels. There is no `token list`, because the Gateway keeps no token registry.

---

# Threat Model

## Leaked Service Token

The attacker cannot read the Provider Credential, the Permissions or the zones. They can use the token within its Permissions. Mitigations: expiry, revocation (which cascades to descendants), audit, and `agent`-only egress for IP-restricted Provider Credentials.

## Gateway database compromise

Reveals only revoked token IDs. No Provider Credentials, Permissions or token records are stored.

## Gateway key compromise

Whoever holds the signing and decryption keys can mint tokens and recover every Provider Credential from any token they hold. These keys are the system's most sensitive asset. Mitigations: keep them in separate files with strict permissions, rotate the encryption key and reseal tokens, and add KMS later.

## Gateway process compromise

A running Gateway decrypts Provider Credentials, so a compromised process can use them. This cannot be fully avoided, since some component must authenticate to the Provider. Mitigations: keep the plaintext credential in memory only briefly, run with least privilege, and keep a strong audit trail.

## Leaked Bound Token (v2)

Useless without a matching Identity Token from the bound Trusted Issuer. If both leak, the attacker can act until the Identity Token expires. See [oidc.md](oidc.md).

## Client machine compromise

A client can perform only what its token allows. With Agent Egress, even root access on the client doesn't expose the Provider Credential, because TLS terminates on the Gateway. Strict certificate verification on the Gateway side defeats DNS poisoning, fake endpoints and certificate manipulation. Recording relayed traffic yields only ciphertext.

## Compromised Gateway attacking a client

The Egress Agent refuses non-443 ports and private, loopback, link-local, CGNAT, ULA and metadata addresses. Accepted risk: connections to arbitrary public hosts on port 443 (ADR 0002).

---

# v1 Scope

1. Onboarding with a bootstrap secret, producing a Root Token
2. JWE(JWS) Service Tokens with ancestor chains
3. Derived Tokens with Narrowing
4. Kubernetes-style Permissions with name patterns
5. Revocation in SQLite, cascading through ancestors
6. Resealing after encryption key rotation
7. Cloudflare adapter (API token)
8. gRPC API with Gateway Egress and Agent Egress
9. Agent Egress destination rules on the client
10. Structured audit logs
11. CLI

Build a prototype of the Agent Egress transport early (gRPC stream relay, `DialContext`, end-to-end TLS), because it is the riskiest part technically.

# v2: ACME Endpoint

Existing ACME clients (acme.sh, lego, cert-manager, certbot, Caddy, Proxmox) are supported through an **ACME Endpoint** that speaks the acme-dns HTTPS API. Full design: [acme.md](acme.md) and [ADR 0003](adr/0003-acme-endpoint.md).

- A separate binary with the Gateway's authorization logic. It holds the encryption private key and the signing public key: it reads tokens but never mints them.
- `POST /update` becomes `patch` (add one value) on a TXT record, authorized by ordinary Permissions. There is no ACME-specific authority.
- A **Challenge Map** in the token maps each acme-dns subdomain to a Challenge Target. Every target must be covered by the token's Permissions.
- `X-Api-User` is the token's `jti`, and `X-Api-Key` is the Service Token. Challenge values must have the DNS-01 shape.
- Gateway Egress only. No `/register`, no cleanup (a per-target value limit applies instead), and no DNS discovery.
- Requires PostgreSQL for the shared revoked-ID list.

# v2: Workload Identity

A Service Token can be bound to a workload's OIDC identity: Kubernetes ServiceAccounts, GitHub Actions and GitLab CI. Full design: [oidc.md](oidc.md) and [ADR 0004](adr/0004-identity-binding-in-service-tokens.md).

- An optional **Identity Binding** inside the token names one Trusted Issuer and exact claim values. A **Bound Token** works only together with a matching **Identity Token**.
- **Trusted Issuers** are an allowlist in Gateway configuration, with audience, signing-key source (discovery, `jwks_uri` or `jwks_file`) and maximum token lifetime.
- The Identity Binding is a Narrowing dimension.
- The Identity Token travels in gRPC stream metadata. The ACME Endpoint rejects Bound Tokens.
- CLI presets bind on immutable IDs (GitHub and GitLab) or on the ServiceAccount `sub` (Kubernetes).

# Later

- PostgreSQL and multiple Gateway replicas (PostgreSQL arrives with the v2 ACME Endpoint)
- KMS for Gateway keys
- Token registry and `token list`
- Client-side hostname allowlist for Agent Egress
- Adapters: external-dns webhook provider, Terraform. cert-manager is covered in v2 by its acmeDNS solver through the ACME Endpoint.
- More Providers, such as Namecheap, whose `setHosts` replaces every record in a zone and needs locking per zone plus a `ClientIp` parameter
- The future Permission constraints listed above
- Kubernetes TokenReview and proof of possession for Identity Tokens

# Open Questions

- ~~Exact claim schema and protobuf API definition.~~ Decided in the protobuf API, [api/dnsgate/v1/gateway.proto](../api/dnsgate/v1/gateway.proto), and the claims in [internal/token/claims.go](../internal/token/claims.go).
- ~~Relay framing inside the gRPC stream: OPEN/DATA/CLOSE messages, half-close, flow control, timeouts.~~ Decided in [ADR 0006](adr/0006-agent-egress-relay-framing.md).
