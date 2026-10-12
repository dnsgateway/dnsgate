# DNS Gateway — ACME Flows (v2)

This document shows how an existing ACME client gets a DNS-01 challenge value written through the ACME Endpoint, `dnsgate-acme`, and the Gateway. It covers who holds which key, and what each party can read.

Background: [acme.md](acme.md) (design), [flows.md](flows.md) (core flows), [ADR 0001](adr/0001-self-contained-service-tokens.md), [ADR 0011](adr/0011-acme-endpoint-is-a-gateway-client.md). Terms: [GLOSSARY.md](../GLOSSARY.md). Claim names and key IDs are examples.

## Keys and who holds them

| Key | Gateway | ACME Endpoint | Client |
|---|---|---|---|
| Signing **private** key (Ed25519), `kid sig-2026-10` | yes, signs new tokens | no | no |
| Signing **public** key | yes, verifies | no | no |
| Encryption **public** key (X25519), `kid enc-2026-10` | yes, encrypts new tokens | no | no |
| Encryption **private** key | yes, decrypts | no | no |
| TLS certificate for the Gateway | yes | no, only trusts it (`--ca-file`) | no |
| TLS certificate for `acme.gateway.example` | no | yes, or the TLS-terminating proxy in front of it | no, only trusts it |

So only the Gateway can mint and read tokens. The ACME Endpoint and the client both hold the token as an opaque string and forward it.

## What is encrypted, and with which key

```text
X-Api-Key: <Service Token>  =  BASE64URL(JWE header) . encrypted key . IV . ciphertext . tag

┌──────────────────────────────────────────────────────────────────────────┐
│ ① JWE header (READABLE by anyone who holds the token)                    │
│    { "typ": "dnsgate+jwe", "alg": "ECDH-ES+A256KW",                      │
│      "enc": "A256GCM", "kid": "enc-2026-10" }                            │
│    → tells the Gateway which ENCRYPTION PRIVATE KEY decrypts it          │
├──────────────────────────────────────────────────────────────────────────┤
│ ② Ciphertext: ENCRYPTED to the Gateway's encryption public key           │
│    (ECDH-ES key agreement wraps a random A256GCM content key)            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ ③ JWS header   { "alg": "EdDSA", "kid": "sig-2026-10" }            │  │
│  │    → tells the Gateway which SIGNING PUBLIC KEY verifies it        │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │ ④ Claims (SIGNED with the signing private key)                     │  │
│  │    iss, aud, sub, jti, iat, nbf, exp, ancestors                    │  │
│  │    provider, credential  ◄── Cloudflare API token                  │  │
│  │    permissions                                                     │  │
│  ├────────────────────────────────────────────────────────────────────┤  │
│  │ ⑤ Ed25519 signature over ③ + ④                                     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```

| Part | Who can read it | Protected by |
|---|---|---|
| ① JWE header (`kid`, algorithms) | anyone | nothing (integrity is covered by AES-GCM) |
| ③ JWS header | Gateway | encryption key |
| ④ Claims, including the **Provider Credential** | Gateway | encryption key (confidentiality) + signing key (authenticity) |
| ⑤ Signature | Gateway | — |

The token carries no Challenge Map. The Challenge Map lives in the ACME Endpoint's configuration. The Provider Credential is not encrypted separately. It is one claim inside ④, protected by the token's single JWE layer. On the network, the token travels inside TLS on both hops: client to ACME Endpoint (or its proxy), and ACME Endpoint to Gateway.

**Visible to the ACME client and the ACME Endpoint:** the opaque token, its `kid`, and the `jti`. The client is given the `jti` separately at issuance, to put in `X-Api-User`. The ACME Endpoint learns it from the Gateway's `InspectToken`.

**Never visible to the ACME client or the ACME Endpoint:** the Cloudflare API token.

---

## 1. Issuing an ACME token

The Administrator issues an ordinary Derived Token through the Gateway with `dnsgate-cli token create`, and adds the matching entries to the ACME Endpoint's Challenge Map. The ACME Endpoint plays no part in issuing.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator (CLI)
    participant GW as Gateway
    participant DB as Revocation store
    participant Log as Audit log
    participant AE as ACME Endpoint config

    Admin->>GW: CreateToken(Parent Token, sub=proxmox-prod,<br/>permissions: patch TXT at targets, egress gateway,<br/>exp=90d)
    GW->>GW: JWE kid=enc-2026-10 → decrypt with ENCRYPTION PRIVATE key
    GW->>GW: JWS kid=sig-2026-10 → verify with SIGNING PUBLIC key
    GW->>GW: Check iss, aud, nbf, exp
    GW->>DB: Is the parent jti or any ancestor revoked?
    DB-->>GW: no
    GW->>GW: Parent grants create on tokens?<br/>Narrowing: child ⊆ parent?
    GW->>GW: New jti, ancestors += parent.jti,<br/>copy provider and credential
    GW->>GW: Sign claims with SIGNING PRIVATE key (kid sig-2026-10)
    GW->>GW: Encrypt with ENCRYPTION PUBLIC key (kid enc-2026-10)
    GW-->>Log: token.create (parent jti, new jti, sub)
    GW-->>Admin: Service Token + jti
    Admin->>AE: Challenge Map: examplecom → example.com / _acme-challenge<br/>(only if not already there)
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
  ]
}
```

There is no `resources` field, so it defaults to `records`. There is no `tokens` resource, so this token can't issue or revoke tokens. Its egress must include the one the ACME Endpoint asks for with `--egress`: `gateway` here, or `agent` for an ACME Endpoint started with `--egress agent`.

---

## 2. The client sets a challenge record (`POST /update`), Gateway Egress

Example: Proxmox renews `example.com`. The client takes the account it has stored for that domain and calls the ACME Endpoint, started with `--egress gateway`.

```mermaid
sequenceDiagram
    autonumber
    participant AC as ACME client<br/>(acme.sh / Proxmox / lego / cert-manager)
    participant AE as ACME Endpoint<br/>(dnsgate-acme)
    participant GW as Gateway
    participant DB as Revocation store
    participant CF as api.cloudflare.com
    participant LE as ACME CA (Let's Encrypt)

    AC->>LE: new order for example.com
    LE-->>AC: DNS-01 challenge (key authorization)
    AC->>AC: txt = base64url(SHA256(keyAuthorization))

    AC->>AE: POST /update (TLS)<br/>X-Api-User: tok_01JACME...<br/>X-Api-Key: Service Token<br/>{"subdomain":"examplecom","txt":"…43 chars…"}

    Note over AE: Local checks, no Gateway call yet
    AE->>AE: JSON well formed? subdomain a DNS label?<br/>txt 43 chars of [A-Za-z0-9_-]?
    AE->>AE: Challenge Map["examplecom"] → example.com / _acme-challenge

    AE->>GW: InspectToken(X-Api-Key)
    GW->>GW: decrypt, verify, check iss/aud/nbf/exp
    GW->>DB: Is the jti or any ancestor revoked?
    DB-->>GW: no
    GW-->>AE: jti = tok_01JACME...
    AE->>AE: X-Api-User == jti?

    AE->>GW: PatchRecord(token X-Api-Key, egress gateway,<br/>example.com, _acme-challenge, TXT, ttl 60,<br/>add ["\"…43 chars…\""])
    Note over GW: Authorize before touching the credential
    GW->>GW: decrypt, verify, check revocation
    GW->>GW: Permission check: patch, records, example.com,<br/>_acme-challenge, TXT, egress gateway
    GW->>CF: read TXT at _acme-challenge.example.com<br/>Authorization: Bearer (credential from ④)
    CF-->>GW: existing values
    alt value already present
        GW-->>AE: OK (no change)
    else
        GW->>CF: add TXT value, ttl 60
        CF-->>GW: created
        GW-->>AE: OK
    end
    Note over GW: Plaintext credential dropped from memory,<br/>audit event records a patch by proxmox-prod
    AE->>AE: log (request ID, subdomain, target, result, duration)
    AE-->>AC: 200 {"txt":"…43 chars…"}

    AC->>LE: challenge ready
    LE->>LE: Resolve TXT _acme-challenge.example.com
    LE-->>AC: valid, certificate issued
    Note over AC,AE: The client's cleanup step does nothing.<br/>The value stays until the Administrator removes it.
```

## 3. The same, with Agent Egress

With `--egress agent`, the ACME Endpoint is the Egress Agent: the Gateway's connection to the Provider is relayed inside the `PatchRecord` stream ([ADR 0006](adr/0006-agent-egress-relay-framing.md)), so the Provider sees the ACME Endpoint's IP. The token needs `agent` in its egress. The Provider Credential stays encrypted end to end inside TLS between the Gateway and the Provider, so the ACME Endpoint relays bytes it cannot read.

```mermaid
sequenceDiagram
    autonumber
    participant AC as ACME client
    participant AE as ACME Endpoint<br/>(Egress Agent)
    participant GW as Gateway
    participant CF as api.cloudflare.com

    AC->>AE: POST /update {"subdomain":"examplecom","txt":"…"}
    AE->>AE: local checks, Challenge Map lookup
    AE->>GW: InspectToken(X-Api-Key)
    GW-->>AE: jti
    AE->>GW: PatchRecord(…, egress agent)
    GW->>GW: authorize: patch, TXT, target, egress agent
    GW->>AE: RelayOpen{id, api.cloudflare.com, 443}
    AE->>AE: destination rules (ADR 0002)
    AE->>CF: TCP connect
    AE-->>GW: RelayOpened{id}
    GW<<->>CF: TLS to the Provider, relayed as RelayData through AE
    GW-->>AE: Response OK
    AE-->>AC: 200 {"txt":"…"}
```

## 4. CNAME delegation

When the Administrator has created `_acme-challenge.example.com CNAME challenge-123.acme.example.net`, the client uses `subdomain: "delegated"`. The ACME Endpoint asks the Gateway to write to `challenge-123.acme.example.net` (zone `example.net`). Neither resolves the CNAME, because the Challenge Map already names the target. Let's Encrypt follows the CNAME itself when it validates.

```mermaid
sequenceDiagram
    autonumber
    participant AC as ACME client
    participant AE as ACME Endpoint
    participant GW as Gateway
    participant CF as api.cloudflare.com
    participant LE as Let's Encrypt

    AC->>AE: POST /update {"subdomain":"delegated","txt":"…"}
    AE->>AE: Challenge Map["delegated"] → example.net / challenge-123.acme
    AE->>GW: InspectToken, then PatchRecord at example.net / challenge-123.acme
    GW->>GW: decrypt, verify, check revocation, Permission check
    GW->>CF: add TXT at challenge-123.acme.example.net
    GW-->>AE: OK
    AE-->>AC: 200 {"txt":"…"}
    LE->>LE: _acme-challenge.example.com<br/>CNAME → challenge-123.acme.example.net → TXT
```

---

## 5. Denied requests

Every authorization failure returns the same answer, so the ACME Endpoint never reveals why a request was refused.

| Situation | Decided by | Reply |
|---|---|---|
| Malformed JSON | ACME Endpoint | 401 `{"error":"forbidden"}` |
| `subdomain` is not a valid DNS label | ACME Endpoint | 400 `{"error":"bad_subdomain"}` |
| `txt` has the wrong shape | ACME Endpoint | 400 `{"error":"bad_txt"}` |
| `subdomain` not in the Challenge Map | ACME Endpoint | 401 `{"error":"forbidden"}` |
| No `X-Api-Key` | ACME Endpoint | 401 `{"error":"forbidden"}` |
| Token can't be decrypted (unknown `kid` or tampered) or the signature is invalid | Gateway (InspectToken) | 401 `{"error":"forbidden"}` |
| Token expired, or its `jti` or an ancestor is revoked | Gateway (InspectToken) | 401 `{"error":"forbidden"}` |
| `X-Api-User` ≠ `jti` | ACME Endpoint | 401 `{"error":"forbidden"}` |
| Permissions don't cover the target, or the token doesn't allow the configured egress | Gateway (PatchRecord) | 401 `{"error":"forbidden"}` |
| Bound Token (no Identity Token can be presented) | Gateway | 401 `{"error":"forbidden"}` |
| TTL below the Provider's minimum | Gateway | 500 `{"error":"provider_error"}` (logged as a configuration error) |
| Cloudflare error | Gateway | 500 `{"error":"provider_error"}` (details in the logs only) |
| Cloudflare refuses the Provider Credential | Gateway | 500 `{"error":"provider_error"}` (details in the logs only) |
| Gateway unreachable or timed out | ACME Endpoint | 500 `{"error":"provider_error"}` (details in the log only) |
