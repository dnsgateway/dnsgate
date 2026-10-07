# DNS Gateway — ACME Flows (v2)

This document shows how an existing ACME client gets a DNS-01 challenge value written through the ACME Endpoint. It covers which parts of the token are readable or encrypted, and which key protects each part.

Background: [acme.md](acme.md) (design), [flows.md](flows.md) (core flows), [ADR 0001](adr/0001-self-contained-service-tokens.md), [ADR 0003](adr/0003-acme-endpoint.md). Terms: [GLOSSARY.md](../GLOSSARY.md). Claim names and key IDs are examples.

## Keys and who holds them

| Key | Gateway | ACME Endpoint | Client |
|---|---|---|---|
| Signing **private** key (Ed25519), `kid sig-2026-10` | yes, signs new tokens | no | no |
| Signing **public** key | yes, verifies | yes, verifies | no |
| Encryption **public** key (X25519), `kid enc-2026-10` | yes, encrypts new tokens | no, not needed | no |
| Encryption **private** key | yes, decrypts | yes, decrypts | no |
| TLS certificate for `acme.gateway.example` | no | yes | no, only trusts it |

So the Gateway can mint and read tokens, the ACME Endpoint can only read them, and the client can do neither.

## What is encrypted, and with which key

```text
X-Api-Key: <Service Token>  =  BASE64URL(JWE header) . encrypted key . IV . ciphertext . tag

┌──────────────────────────────────────────────────────────────────────────┐
│ ① JWE header (READABLE by anyone who holds the token)                    │
│    { "typ": "dnsgate+jwe", "alg": "ECDH-ES+A256KW",                      │
│      "enc": "A256GCM", "kid": "enc-2026-10" }                            │
│    → tells the ACME Endpoint which ENCRYPTION PRIVATE KEY decrypts it    │
├──────────────────────────────────────────────────────────────────────────┤
│ ② Ciphertext: ENCRYPTED to the Gateway's encryption public key           │
│    (ECDH-ES key agreement wraps a random A256GCM content key)            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ③ JWS header   { "alg": "EdDSA", "kid": "sig-2026-10" }            │  │
│  │    → tells the reader which SIGNING PUBLIC KEY verifies it         │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │ ④ Claims (SIGNED with the signing private key)                     │  │
│  │    iss, aud, sub, jti, iat, nbf, exp, ancestors                    │  │
│  │    provider, credential  ◄── Cloudflare API token                  │  │
│  │    permissions                                                     │  │
│  │    acme.challenges       ◄── Challenge Map                         │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │ ⑤ Ed25519 signature over ③ + ④                                     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

| Part | Who can read it | Protected by |
|---|---|---|
| ① JWE header (`kid`, algorithms) | anyone | nothing (integrity is covered by AES-GCM) |
| ③ JWS header | Gateway, ACME Endpoint | encryption key |
| ④ Claims, including the **Provider Credential** and the **Challenge Map** | Gateway, ACME Endpoint | encryption key (confidentiality) + signing key (authenticity) |
| ⑤ Signature | Gateway, ACME Endpoint | — |

The Provider Credential is not encrypted separately. It is one claim inside ④, protected by the token's single JWE layer. On the network, the whole request travels inside TLS to `acme.gateway.example`.

**Visible to the ACME client:** the opaque token, its `kid`, and the `jti`. The client is given the `jti` separately at issuance, to put in `X-Api-User`. It is not readable from the token.

**Never visible to the ACME client:** the Cloudflare API token, the Permissions, the Challenge Targets, the Service Account, and the token's expiry.

---

## 1. Issuing an ACME token

The Administrator uses the Gateway's gRPC API. The ACME Endpoint plays no part in issuing.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator (CLI)
    participant GW as Gateway
    participant DB as PostgreSQL (revoked IDs)
    participant Log as Audit log

    Admin->>GW: CreateToken(Parent Token, sub=proxmox-prod,<br/>permissions: patch TXT at targets, egress gateway,<br/>acme.challenges: {examplecom → example.com/_acme-challenge},<br/>exp=90d)
    GW->>GW: JWE kid=enc-2026-10 → decrypt with ENCRYPTION PRIVATE key
    GW->>GW: JWS kid=sig-2026-10 → verify with SIGNING PUBLIC key
    GW->>GW: Check iss, aud, nbf, exp
    GW->>DB: Is the parent jti or any ancestor revoked?
    DB-->>GW: no
    GW->>GW: Parent grants create on tokens?<br/>Narrowing: child ⊆ parent?
    GW->>GW: Every Challenge Map target is covered by the<br/>child's Permissions (patch, TXT)?
    GW->>GW: New jti, ancestors += parent.jti,<br/>copy provider and credential
    GW->>GW: Sign claims with SIGNING PRIVATE key (kid sig-2026-10)
    GW->>GW: Encrypt with ENCRYPTION PUBLIC key (kid enc-2026-10)
    GW-->>Log: token.create (parent jti, new jti, sub)
    GW-->>Admin: Service Token + jti + subdomains<br/>+ CNAMEs to create (when delegating)
    Admin->>Admin: Configure the client:<br/>username=jti, password=token,<br/>subdomain=examplecom, base URL
```

**What's inside the ACME token** (claims ④, after decryption):

```json
{
  "iss": "dnsgate",
  "aud": "dnsgate",
  "sub": "proxmox-prod",
  "jti": "tok_01JACME...",
  "iat": 1791417600,
  "nbf": 1791417600,
  "exp": 1799193600,
  "ancestors": ["tok_01JROOT..."],

  "provider": "cloudflare",
  "credential": { "type": "api-token", "value": "<Cloudflare API token>" },

  "permissions": [
    {
      "verbs": ["patch"],
      "zones": ["example.com"],
      "names": ["_acme-challenge"],
      "types": ["TXT"],
      "egress": ["gateway"]
    },
    {
      "verbs": ["patch"],
      "zones": ["example.net"],
      "names": ["challenge-123.acme"],
      "types": ["TXT"],
      "egress": ["gateway"]
    }
  ],

  "acme": {
    "challenges": {
      "examplecom": { "zone": "example.com", "name": "_acme-challenge" },
      "delegated":  { "zone": "example.net", "name": "challenge-123.acme" }
    }
  }
}
```

There is no `resources` field, so it defaults to `records`. There is no `tokens` resource, so this token can't issue or revoke tokens. Its only egress is `gateway`, because the ACME Endpoint can't relay through the client.

---

## 2. The client sets a challenge record (`POST /update`)

Example: Proxmox renews `example.com`. The client takes the account it has stored for that domain and calls the ACME Endpoint.

```mermaid
sequenceDiagram
    autonumber
    participant AC as ACME client<br/>(acme.sh / Proxmox / lego / cert-manager)
    participant AE as ACME Endpoint
    participant DB as PostgreSQL (revoked IDs)
    participant CF as api.cloudflare.com
    participant LE as ACME CA (Let's Encrypt)
    participant Log as Audit log

    AC->>LE: new order for example.com
    LE-->>AC: DNS-01 challenge (key authorization)
    AC->>AC: txt = base64url(SHA256(keyAuthorization))

    AC->>AE: POST /update (TLS)<br/>X-Api-User: tok_01JACME...<br/>X-Api-Key: Service Token<br/>{"subdomain":"examplecom","txt":"…43 chars…"}

    Note over AE: Authorize before touching the credential
    AE->>AE: ① JWE kid=enc-2026-10 → decrypt with ENCRYPTION PRIVATE key
    AE->>AE: ③ JWS kid=sig-2026-10 → verify with SIGNING PUBLIC key
    AE->>AE: Check iss, aud, nbf, exp
    AE->>DB: Is the jti or any ancestor revoked?
    DB-->>AE: no
    AE->>AE: X-Api-User == jti?
    AE->>AE: Challenge Map["examplecom"] → example.com / _acme-challenge
    AE->>AE: Permission check: patch, records, example.com,<br/>_acme-challenge, TXT, egress gateway
    AE->>AE: txt is 43 chars of [A-Za-z0-9_-]?

    AE->>CF: GET /zones?name=example.com<br/>Authorization: Bearer (credential from ④)
    CF-->>AE: zone id
    AE->>CF: GET TXT records at _acme-challenge.example.com
    CF-->>AE: existing values

    alt value already present
        AE-->>Log: acme.update (result: exists)
        AE-->>AC: 200 {"txt":"…43 chars…"} (idempotent)
    else values ≥ maxValuesPerTarget (default 20)
        AE-->>Log: acme.update (result: limit reached)
        AE-->>AC: 400 {"error":"bad_txt"}
    else
        AE->>CF: POST /zones/{id}/dns_records<br/>{type TXT, name _acme-challenge.example.com,<br/>content txt, ttl from config (60)}
        CF-->>AE: created
        AE-->>Log: acme.update (jti, sub, subdomain, target, result: added)
        AE-->>AC: 200 {"txt":"…43 chars…"}
    end
    Note over AE: Plaintext credential dropped from memory in every branch

    AC->>LE: challenge ready
    LE->>LE: Resolve TXT _acme-challenge.example.com
    LE-->>AC: valid, certificate issued
    Note over AC,AE: The client's cleanup step does nothing.<br/>The value stays until the Administrator removes it.
```

### With CNAME delegation

When the Administrator has created `_acme-challenge.example.com CNAME challenge-123.acme.example.net`, the client uses `subdomain: "delegated"`. The ACME Endpoint writes to `challenge-123.acme.example.net` (zone `example.net`). It never resolves the CNAME, because the Challenge Map already names the target. Let's Encrypt follows the CNAME itself when it validates.

```mermaid
sequenceDiagram
    autonumber
    participant AC as ACME client
    participant AE as ACME Endpoint
    participant CF as api.cloudflare.com
    participant LE as Let's Encrypt

    AC->>AE: POST /update {"subdomain":"delegated","txt":"…"}
    AE->>AE: decrypt, verify, check revocation, Challenge Map["delegated"]<br/>→ example.net / challenge-123.acme, Permission check
    AE->>CF: add TXT at challenge-123.acme.example.net
    AE-->>AC: 200 {"txt":"…"}
    LE->>LE: _acme-challenge.example.com<br/>CNAME → challenge-123.acme.example.net → TXT
```

---

## 3. Denied requests

Every authorization failure returns the same answer, so the ACME Endpoint never reveals why a request was refused.

| Situation | Reply |
|---|---|
| Token can't be decrypted (unknown `kid` or tampered) or the signature is invalid | 401 `{"error":"forbidden"}` |
| Token expired, or its `jti` or an ancestor is revoked | 401 `{"error":"forbidden"}` |
| `X-Api-User` ≠ `jti` | 401 `{"error":"forbidden"}` |
| `subdomain` not in the Challenge Map | 401 `{"error":"forbidden"}` |
| Permissions don't cover the target, or the token lacks `gateway` egress | 401 `{"error":"forbidden"}` |
| `subdomain` is not a valid DNS label | 400 `{"error":"bad_subdomain"}` |
| `txt` has the wrong shape, or the target is at its value limit | 400 `{"error":"bad_txt"}` |
| Cloudflare error | 500 `{"error":"provider_error"}` (details go to audit only) |
