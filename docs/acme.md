# DNS Gateway — ACME Endpoint (v2)

## Goal

Let existing ACME clients complete DNS-01 challenges through the Gateway without ever receiving the Provider Credential, and with no changes to the clients.

The compatibility target is the **acme-dns HTTPS API** (`POST /update`, `GET /health`). Almost every ACME client already supports it: acme.sh, lego, cert-manager, certbot, Caddy and Proxmox.

This document builds on the core architecture in [draft.md](draft.md). Terms are defined in [GLOSSARY.md](../GLOSSARY.md). Decisions are in [ADR 0001](adr/0001-self-contained-service-tokens.md) and [ADR 0003](adr/0003-acme-endpoint.md).

---

# Main Principle

ACME is **not** a new kind of authority. An acme-dns `/update` is translated into a `patch` (add one value) on a TXT record, and the token's ordinary Permissions authorize it. The Challenge Map in the token only says *which* Challenge Target a subdomain refers to.

DNS resolution never grants permission. The ACME Endpoint never follows CNAMEs or looks up DNS at all.

---

# ACME Endpoint

- **A separate binary**, so it can scale independently of the Gateway, with the same authorization logic as the Gateway.
- **Keys:** it holds the **encryption private key** and the **signing public key**. It can read tokens but cannot mint them.
- **State:** it reads the shared revoked-ID list from **PostgreSQL**. Deployments with an ACME Endpoint require PostgreSQL.
- **Hostname:** it is served over HTTPS on its own hostname, for example `https://acme.gateway.example`.
- **Egress:** **Gateway Egress only**. acme-dns clients send one-shot HTTPS requests and cannot act as an Egress Agent. A token whose Permissions allow only `agent` egress is rejected.
- **Bound Tokens:** rejected. acme-dns clients cannot present an Identity Token ([oidc.md](oidc.md)).

```text
ACME client (acme.sh, lego, cert-manager, ...)
      │  POST /update   X-Api-User / X-Api-Key / {subdomain, txt}
      ▼
ACME Endpoint ── revoked IDs ──► PostgreSQL (shared with the Gateway)
      │  HTTPS from the Gateway's infrastructure
      ▼
Provider (Cloudflare)
```

---

# Tokens for ACME

An ACME client uses an ordinary **Derived Token** that has:

- a Permission allowing `patch` on TXT records at each Challenge Target;
- `gateway` in its egress (or no egress filter at all, which means any egress);
- a **Challenge Map** from acme-dns subdomain to Challenge Target.

```json
{
  "sub": "proxmox-prod",
  "jti": "tok_01JACME...",
  "exp": 1799193600,
  "ancestors": ["tok_01JROOT..."],
  "provider": "cloudflare",
  "credential": { "type": "api-token", "value": "..." },

  "permissions": [
    {
      "verbs": ["patch"],
      "zones": ["example.com"],
      "names": ["_acme-challenge", "_acme-challenge.www"],
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
      "examplecom":  { "zone": "example.com", "name": "_acme-challenge" },
      "wwwexample":  { "zone": "example.com", "name": "_acme-challenge.www" },
      "delegated":   { "zone": "example.net", "name": "challenge-123.acme" }
    }
  }
}
```

`resources` is left out of both Permissions, so it defaults to `records`. Claim names are examples.

## Challenge Map rules

- Each key is an acme-dns **subdomain**: a single DNS label (`[A-Za-z0-9-]`, at most 63 characters, not starting or ending with `-`).
- Each value names a Challenge Target by zone and zone-relative name.
- **The map grants nothing.** When a token is issued, the Gateway rejects any map entry whose Challenge Target isn't covered by the new token's own Permissions (`patch` on TXT). At request time, the ACME Endpoint checks both the map and the Permissions.
- A child token's map does not have to be a subset of its parent's. Every target must be covered by the child's Permissions, and those are already narrowed.
- One token can serve several certificate domains, one map entry per domain.

## Direct and delegated challenges

The Challenge Target is simply whatever name the token allows, so every way of delegating a challenge works without special handling:

| Mode | DNS (created once by the Administrator) | Challenge Target |
|---|---|---|
| Direct | none | `_acme-challenge.example.com` |
| CNAME delegation | `_acme-challenge.example.com CNAME challenge-123.acme.example.net` | `challenge-123.acme.example.net` |
| NS delegation | `_acme-challenge.example.com NS ns1.validation.example.net` | a TXT name in the delegated zone, which the credential reaches |

The ACME Endpoint never checks these delegations. If DNS points somewhere else, ACME validation fails, but no permission is ever granted by DNS.

---

# API

## `POST /update`

Request (exactly what every acme-dns client sends):

```http
POST /update
X-Api-User: tok_01JACME...
X-Api-Key: <Service Token>
Content-Type: application/json

{"subdomain": "examplecom", "txt": "<43-char base64url challenge value>"}
```

- **`X-Api-Key`** carries the full Service Token. Clients don't limit its length (checked in acme.sh, lego/goacmedns, cert-manager, certbot-dns-acmedns, Caddy and Proxmox).
- **`X-Api-User`** must equal the token's `jti`. A mismatch returns 401.
- **`subdomain`** must be a key in the token's Challenge Map.
- **`txt`** must be exactly 43 characters of `[A-Za-z0-9_-]` (unpadded base64url of a SHA-256 digest). Anything else is rejected, so an ACME token can't write arbitrary TXT values.

Processing:

```text
decrypt (JWE kid) → verify (JWS kid) → check iss/aud/nbf/exp
  → check jti and ancestors against revoked IDs (PostgreSQL)
  → X-Api-User == jti
  → look up subdomain in the Challenge Map → Challenge Target
  → check Permissions: patch, records, zone, name, TXT, gateway egress
  → check the txt shape
  → read the TXT RRset at the Challenge Target
       value already present? → 200 (idempotent)
       value count ≥ acme.maxValuesPerTarget? → 400 bad_txt
  → add the value with TTL from configuration
  → audit event → 200
```

## Response contract

Clients depend on these exact status codes and bodies:

| Case | Status | Body |
|---|---|---|
| Success, including a value that already exists | **200** (exactly; certbot and Caddy require it) | `{"txt": "<value>"}`. acme.sh looks for the value in the body. |
| Any authentication or authorization failure: bad or revoked token, `X-Api-User` mismatch, subdomain not in map, Permission missing, egress not allowed, malformed JSON | 401 | `{"error": "forbidden"}` |
| `subdomain` is not a valid DNS label | 400 | `{"error": "bad_subdomain"}` |
| `txt` has the wrong shape, or the target is at its value limit | 400 | `{"error": "bad_txt"}` |
| Provider failure | 500 | `{"error": "provider_error"}` (details go to audit only) |

## `GET /health`

Returns 200 with an empty body.

## `POST /register`

**Not supported** (404). Tokens are provisioned statically by an Administrator. Clients that register automatically when they have no credentials (acme.sh, lego, the acme-dns-auth certbot hook) must be given credentials in advance.

---

# No Cleanup

The ACME Endpoint **only adds** challenge values. It never deletes or prunes them: no timer, no rule based on age or count.

- None of the acme-dns clients ever asks for removal. Their cleanup step does nothing.
- Deleting later would need the Provider Credential after the request is over, which conflicts with ADR 0001.
- Pruning by count can race with another validation still running at a shared Challenge Target.

Consequences:

- Values pile up at each Challenge Target, roughly two per renewal plus retries. The Administrator removes them with `dnsgate-cli record patch` (removing values) or `dnsgate-cli record delete`.
- To stop a client stuck in a retry loop from filling the zone, the ACME Endpoint **refuses** to add new values once a target holds `acme.maxValuesPerTarget` values (default 20), replying `400 bad_txt` until someone cleans up.

---

# Configuration

```yaml
acme:
  listen: ":8443"
  hostname: acme.gateway.example
  ttl: 60                 # raised to the Provider's minimum if that is higher
  maxValuesPerTarget: 20
```

TTL isn't a security boundary, so it lives in configuration and not in the token.

---

# Client Compatibility

| Client | Settings | Notes |
|---|---|---|
| acme.sh `dns_acmedns` | `ACMEDNS_BASE_URL`, `ACMEDNS_USERNAME` (jti), `ACMEDNS_PASSWORD` (token), `ACMEDNS_SUBDOMAIN` | Registers automatically if credentials are empty, so always set them. |
| Proxmox VE | Same four settings as acme.sh (it runs the acme.sh plugin) | Discards automatic registrations, so credentials must be set. Settings are split on whitespace, which a base64url token doesn't contain. |
| lego `acmedns` | `ACME_DNS_API_BASE`, storage file with the account for each domain | Registers if the storage has no entry for a domain, so prefill it. |
| cert-manager `acmeDNS` solver | `host`, plus a Secret holding a JSON map from domain to account | Never registers. |
| certbot-dns-acmedns | `api-url`, a registration file keyed by domain | Never registers. Requires exactly 200. |
| acme-dns-auth.py certbot hook | `ACMEDNS_URL`, a stored account for each domain | Requires exactly 200. **Prints `X-Api-Key` to stdout when an update fails.** |
| Caddy `caddy-dns/acmedns` | `server_url`, username, password, subdomain (or a map for each domain) | Requires exactly 200. |

The account fields map the same way for every client:

```text
username   = token jti
password   = Service Token
subdomain  = a key in the token's Challenge Map
fulldomain = the Challenge Target (used by the client only to print the CNAME to create)
```

---

# Security Notes

- **Expect ACME tokens to leak into logs.** Some clients print `X-Api-Key` when an update fails. Keep ACME tokens narrow: `patch` on TXT at the Challenge Targets only, no `tokens` resource, and a mandatory expiry.
- **The certificate domain is never sent** by any client, only the subdomain and the value. Authorization is therefore by Challenge Target, and the certificate domain cannot be checked on the server.
- **Checking the value's shape** stops the token from being used to write arbitrary TXT values (SPF, domain verification strings). It doesn't prove the caller holds a real ACME authorization.
- **The ACME Endpoint can read every token it receives.** Compromising it exposes Provider Credentials, but it cannot mint tokens.

---

# Audit Logging

Every `/update` (successful or denied) produces a structured JSON event with these fields: timestamp, request ID, Service Account, token `jti`, subdomain, Challenge Target (zone and name), result, Provider status, duration.

Never logged: the Service Token, the Provider Credential, `X-Api-Key`.

---

# v2 Scope

1. ACME Endpoint binary with `POST /update` and `GET /health`
2. Challenge Map in tokens, checked against Permissions when a token is issued
3. TXT value shape check, adding values without duplicates, and the per-target value limit
4. Shared revocation state in PostgreSQL
5. Gateway Egress
6. The response contract above
7. Integration tests against acme.sh, lego and cert-manager

Not planned: `/register`, automatic cleanup, DNS or CNAME discovery, checking delegations, Agent Egress on this endpoint.
