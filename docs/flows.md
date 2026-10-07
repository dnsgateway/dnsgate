# DNS Gateway — Core Flows

These sequence diagrams show the three core flows, using the terms in [GLOSSARY.md](../GLOSSARY.md). The decisions behind them are in [ADR 0001](adr/0001-self-contained-service-tokens.md) and [ADR 0002](adr/0002-gateway-names-agent-egress-destination.md).

Claim names and key IDs are examples. The exact schema is not fixed yet.

## Keys

The Gateway holds two key pairs. Both are PEM files in v1.

| Key | Used for | Where its ID appears |
|---|---|---|
| Signing key (Ed25519) | Signing claims (inner JWS) | `kid` in the **inner** JWS header, e.g. `sig-2026-10` |
| Encryption key (X25519, ECDH-ES+A256KW / A256GCM) | Encrypting the signed token (outer JWE) | `kid` in the **outer** JWE header, e.g. `enc-2026-10` |

The outer JWE header is the only part of a Service Token a client can read. It tells the Gateway which decryption key to use. After decrypting, the inner JWS header tells the Gateway which public key verifies the signature.

When an encryption key is rotated, old decryption keys are kept by `kid` until their retirement deadline. Resealing re-encrypts a token under the current `kid` without changing its claims.

```text
Service Token (what the client holds)
┌───────────────────────────────────────────────────────────────┐
│ JWE header (readable)  { "typ": "dnsgate+jwe",                │
│                          "alg": "ECDH-ES+A256KW",             │
│                          "enc": "A256GCM",                    │
│                          "kid": "enc-2026-10" }               │
├───────────────────────────────────────────────────────────────┤
│ ciphertext (only the Gateway can decrypt)                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ JWS header  { "alg": "EdDSA", "kid": "sig-2026-10" }    │  │
│  │ claims      { iss, aud, sub, jti, iat, nbf, exp,        │  │
│  │               ancestors, provider, credential,          │  │
│  │               permissions }                             │  │
│  │ signature                                               │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

---

## 1. Onboarding: creating the Root Token

The Administrator handles the plaintext Provider Credential only in this flow.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator (CLI)
    participant GW as Gateway
    participant Log as Audit log

    Admin->>GW: Onboard(bootstrap secret, provider=cloudflare,<br/>credential={type: api-token, value})<br/>[gRPC over TLS]
    GW->>GW: Check bootstrap secret
    GW->>GW: New jti = tok_ROOT, ancestors = []
    GW->>GW: Claims with full Permissions,<br/>no exp unless --expires is set
    GW->>GW: Sign with signing key (kid sig-2026-10)
    GW->>GW: Encrypt with encryption key (kid enc-2026-10)
    GW->>GW: Drop the plaintext credential from memory
    GW-->>Log: onboard event (jti, provider, no secrets)
    GW-->>Admin: Root Token (opaque JWE)
```

**What's inside the Root Token** (after decryption):

```json
{
  "iss": "dnsgate",
  "aud": "dnsgate",
  "sub": "admin",
  "jti": "tok_01JROOT...",
  "iat": 1791417600,
  "nbf": 1791417600,
  "ancestors": [],

  "provider": "cloudflare",
  "credential": { "type": "api-token", "value": "<Cloudflare API token>" },

  "permissions": [
    {
      "verbs": ["get", "list", "create", "update", "patch", "delete"],
      "resources": ["zones", "records", "tokens"],
      "zones": ["*"],
      "names": ["@", "**"],
      "types": ["*"],
      "egress": ["gateway", "agent"]
    }
  ]
}
```

There is no `exp`, because a Root Token does not expire unless `--expires` is set. `zones: ["*"]` means every zone the Provider Credential can reach. `types: ["*"]` means every record type.

---

## 2. Issuing a Derived Token for a client

The Administrator presents the Root Token, or any token holding `create` on `tokens`, and asks for narrower permissions.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator (CLI)
    participant GW as Gateway
    participant DB as Revoked IDs (SQLite)
    participant Log as Audit log

    Admin->>GW: CreateToken(Parent Token,<br/>sub=external-dns-prod, permissions, exp=90d)
    GW->>GW: Read JWE kid=enc-2026-10, then decrypt
    GW->>GW: Read JWS kid=sig-2026-10, then verify signature
    GW->>GW: Check iss, aud, nbf, exp
    GW->>DB: Is the parent's jti or any ancestor revoked?
    DB-->>GW: no
    GW->>GW: Does the Parent Token grant create on tokens?
    GW->>GW: Narrowing: requested permissions ⊆ parent's,<br/>exp ≤ parent's exp, chain depth OK
    GW->>GW: New jti = tok_CHILD,<br/>ancestors = parent.ancestors + [parent.jti]
    GW->>GW: Copy provider and credential from the parent
    GW->>GW: Sign (kid sig-2026-10), encrypt (current kid enc-2026-10)
    GW-->>Log: token.create event (parent jti, new jti, sub)
    GW-->>Admin: Derived Token (opaque JWE)
    Admin->>Admin: Hand the token to the client<br/>(e.g. a Kubernetes Secret)
```

**What's inside the Derived Token**:

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
  "credential": { "type": "api-token", "value": "<copied from parent>" },

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

This token has no `tokens` resource, so it cannot issue further tokens. Because its egress is `agent` only, a stolen copy can only reach Cloudflare from the thief's own IP.

---

## 3. Creating, updating or deleting a DNS record

The client sends one gRPC bidirectional stream per request. For Agent Egress, the relay runs inside that same stream.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (CLI) / Egress Agent
    participant GW as Gateway
    participant DB as Revoked IDs (SQLite)
    participant CF as api.cloudflare.com
    participant Log as Audit log

    C->>GW: Open stream: Service Token +<br/>records.create {zone example.com, name www.apps,<br/>type A, value 192.0.2.10, ttl 300}, egress=agent

    Note over GW: Authorize before touching the credential
    GW->>GW: Decrypt (JWE kid) and verify (JWS kid)
    GW->>GW: Check iss, aud, nbf, exp
    GW->>DB: Is the jti or any ancestor revoked?
    DB-->>GW: no
    GW->>GW: Permission check: verb, resource=records, zone,<br/>name pattern, type, egress<br/>(no egress in request: gateway if allowed)

    alt egress = gateway
        GW->>CF: TLS from the Gateway's IP
    else egress = agent
        GW->>C: OPEN api.cloudflare.com:443 (on the same stream)
        C->>C: Port must be 443. Resolve the hostname and refuse<br/>loopback, RFC1918, link-local, CGNAT, ULA,<br/>169.254.169.254
        C->>CF: TCP connect from the client's IP
        GW-->>CF: TLS handshake end-to-end through the relay<br/>(client sees only ciphertext)
    end

    GW->>CF: GET /zones?name=example.com (look up zone id)
    CF-->>GW: zone id

    alt create
        GW->>CF: POST /zones/{id}/dns_records
    else update (replace the whole RRset)
        GW->>CF: GET existing records for name and type
        GW->>CF: PUT, POST or DELETE so the RRset matches the request
    else delete
        GW->>CF: GET existing records for name and type
        GW->>CF: DELETE /zones/{id}/dns_records/{record_id}
    end
    Note over GW,CF: Authorization: Bearer (credential)<br/>exists only inside TLS between Gateway and Cloudflare

    CF-->>GW: response
    GW->>GW: Map to a Gateway result or error category<br/>(drop the plaintext credential)
    GW-->>Log: mutation event (jti, sub, zone, name, type, verb,<br/>requested and actual egress, result, provider status)
    GW-->>C: Result (filtered to what the token covers)
```

**What the client knows:** the opaque token and its outer `kid`, the request it sent, and the mapped result.

**What the client never sees:** the Cloudflare API token, the token's permissions, and the HTTP traffic between the Gateway and Cloudflare.
