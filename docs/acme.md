# DNS Gateway — ACME Endpoint (v2)

## Goal

Let existing ACME clients complete DNS-01 challenges through the Gateway without ever receiving the Provider Credential, and with no changes to the clients.

The ACME Endpoint speaks two HTTPS APIs on one listener:

- the **acme-dns API** (`POST /update`, `GET /health`), which almost every ACME client already supports: acme.sh, lego, cert-manager, certbot, Caddy and Proxmox;
- the **acmeproxy API** (`POST /present`, `POST /cleanup`), the HTTP "present / cleanup" protocol of lego's `httpreq` provider (and Traefik, built on lego), acme.sh's `dns_acmeproxy` hook and the Caddy / libdns `acmeproxy` module.

This document builds on the core architecture in [draft.md](draft.md). Terms are defined in [GLOSSARY.md](../GLOSSARY.md). Decisions are in [ADR 0001](adr/0001-self-contained-service-tokens.md) and [ADR 0011](adr/0011-acme-endpoint-is-a-gateway-client.md). ADR 0011 supersedes [ADR 0003](adr/0003-acme-endpoint.md) and is amended by [ADR 0012](adr/0012-unmapped-subdomain-is-the-certificate-domain.md) and [ADR 0013](adr/0013-acme-endpoint-speaks-acmeproxy-and-cleans-up-on-request.md).

---

# Main Principle

ACME is **not** a new kind of authority. An acme-dns `/update` or an acmeproxy `/present` is translated into a `patch` that adds one value on a TXT record, and an acmeproxy `/cleanup` into a `patch` that removes one value, sent to the Gateway with the caller's own Service Token. The Gateway authorizes it with the token's ordinary Permissions, exactly as it would a `dnsgate-cli record patch`. The Challenge Map only says *which* Challenge Target an acme-dns subdomain refers to; an acmeproxy client names the Challenge Target itself.

DNS resolution never grants permission. The ACME Endpoint never follows CNAMEs or looks up DNS at all.

---

# ACME Endpoint

The ACME Endpoint is `dnsgate-acme`, a separate daemon next to `dnsgate` and `dnsgate-cli`, shipped as its own release binary and container image.

- **A Gateway client.** It calls the Gateway API through the dnsgate-go client, like `dnsgate-cli`. It never opens tokens itself: the Gateway does all the authorization (decryption, signature, expiry, Revocation, Permissions, Egress).
- **Keys:** none. It never sees a Provider Credential in plaintext. Compromising it exposes the tokens sent to it while it is compromised, but none of the Gateway's keys.
- **State:** none. It needs no PostgreSQL, so several ACME Endpoints can run behind a load balancer.
- **Serving:** HTTPS on its own hostname (for example `https://acme.gateway.example`), or plain HTTP behind a TLS-terminating proxy or Kubernetes ingress.
- **Egress:** chosen with `--egress`. With `gateway`, the Provider sees the Gateway's IP. With `agent`, the ACME Endpoint relays the Gateway's connection as an Egress Agent, so the Provider sees the ACME Endpoint's IP. The destination rules of [ADR 0002](adr/0002-gateway-names-agent-egress-destination.md) apply on the ACME Endpoint's host.
- **Bound Tokens:** refused (401). acme-dns clients cannot present an Identity Token ([oidc.md](oidc.md)), so the Gateway refuses the token.

```text
ACME client (acme.sh, lego, cert-manager, Traefik, Caddy, ...)
      │  acme-dns:   POST /update             X-Api-User / X-Api-Key  {subdomain, txt}
      │  acmeproxy:  POST /present, /cleanup  Basic auth jti:token    {fqdn, value}
      ▼
dnsgate-acme (ACME Endpoint)  ── Challenge Map file
      │  gRPC over TLS: InspectToken, PatchRecord (token unchanged)
      ▼
Gateway ── revoked IDs ──► its revocation store
      │  Gateway Egress, or Agent Egress relayed by dnsgate-acme
      ▼
Provider (Cloudflare)
```

---

# Flags

Each flag falls back to an environment variable, then to a default. The three Gateway client flags keep the names and environment variables of `dnsgate-cli`.

| Flag | Environment variable | Default | Meaning |
|---|---|---|---|
| `--listen` | `DNSGATE_ACME_LISTEN_ADDRESS` | `:8080` | Address to serve the acme-dns and acmeproxy APIs on |
| `--tls-cert-file` | `DNSGATE_ACME_TLS_CERT_FILE` | none | TLS certificate to serve HTTPS with |
| `--tls-key-file` | `DNSGATE_ACME_TLS_KEY_FILE` | none | Key of that certificate |
| `--challenge-map` | `DNSGATE_ACME_CHALLENGE_MAP` | none | Challenge Map file (YAML or JSON); without it every subdomain is unmapped. The acmeproxy API never uses it |
| `--ttl` | `DNSGATE_ACME_TTL` | `60` | TTL of the challenge values it adds |
| `--log-level` | `DNSGATE_ACME_LOG_LEVEL` | `info` | Log level |
| `--gateway` | `DNSGATE_GATEWAY` | `localhost:8443` | Gateway address |
| `--ca-file` | `DNSGATE_CA_FILE` | the system's CAs | CA certificates that verify the Gateway (repeatable) |
| `--egress` | `DNSGATE_EGRESS` | none | `gateway` or `agent`; when unset, the Gateway chooses (Gateway Egress if the token allows it, else Agent Egress) |

The daemon stops at startup, with a clear error, when:

- `--egress` is neither `gateway` nor `agent`;
- a Challenge Map file is given but can't be read or has an invalid entry (a key that isn't a single DNS label, an entry without a name, or an entry without a zone whose name is `@`);
- only one of `--tls-cert-file` and `--tls-key-file` is given. A half-configured TLS setup never falls back to HTTP.

TTL isn't a security boundary, so it lives in configuration and not in the token. The Gateway refuses a TTL below the Provider's minimum, so set `--ttl` to at least that.

---

# Challenge Map

The Challenge Map is an optional file in the ACME Endpoint's configuration, used by the acme-dns API only. It maps each acme-dns subdomain to a Challenge Target by zone and zone-relative name:

```yaml
examplecom:
  zone: example.com
  name: _acme-challenge
wwwexample:
  zone: example.com
  name: _acme-challenge.www
delegated:
  zone: example.net
  name: challenge-123.acme
anyzone:
  name: _acme-challenge.example.org
tokenzone:
  name: _acme-challenge
```

## Rules

- Each key is an acme-dns **subdomain**: a single DNS label (`[A-Za-z0-9-]`, at most 63 characters, not starting or ending with `-`).
- Each value names a Challenge Target by zone and zone-relative name. The name is required; the zone is optional.
- Without a zone, the zone is taken from the token on each `/update`, so such an entry accepts any domain a token reaches:
  - as an absolute name (`_acme-challenge.example.org`), the longest zone named in the token's Permissions that holds the name and allows `patch` on TXT there;
  - failing that, if the name is a single label (`_acme-challenge`), as a name in any zone: the one zone named in the token's Permissions that allows `patch` on TXT at that name. A token whose Permissions allow it in more than one zone is refused, since the request does not say which. A name with a dot is always absolute, so it never lands in a zone that does not hold it.

  A token whose Permissions name no such zone (a `*` zones entry names none) is refused with 401 `forbidden`, without a call to the Provider. The name cannot be `@`.
- The file is read and checked once, at startup.
- A **subdomain not in the map** is taken as the Certificate Domain, so a client may send the domain itself (`www.example.com`, `*.example.com`) as its subdomain ([ADR 0012](adr/0012-unmapped-subdomain-is-the-certificate-domain.md)). Its Challenge Target is `_acme-challenge` in front of the domain, without a zone, resolved as above: the longest zone of the token that holds it. Case, a trailing dot, and a leading `*.` or `_acme-challenge` label are ignored. An unmapped single label names `_acme-challenge` in the one zone the token allows. Grant such tokens `names: ["_acme-challenge", "_acme-challenge.**"]` to cover subdomains of the zone.
- **The map grants nothing, and does not limit the targets.** A subdomain, in the map or not, is writable only with a token whose Permissions allow `patch` on TXT at its Challenge Target. The Gateway checks that on every write, so the token's Permissions, not the map, are what bound an ACME token.
- One map serves every token and every certificate domain sent to that ACME Endpoint. Run one ACME Endpoint for many clients.

## Direct and delegated challenges

The Challenge Target is simply whatever name the map names and the token allows, so every way of delegating a challenge works without special handling:

| Mode | DNS (created once by the Administrator) | Challenge Target |
|---|---|---|
| Direct | none | `_acme-challenge.example.com` |
| CNAME delegation | `_acme-challenge.example.com CNAME challenge-123.acme.example.net` | `challenge-123.acme.example.net` |
| NS delegation | `_acme-challenge.example.com NS ns1.validation.example.net` | a TXT name in the delegated zone, which the credential reaches |

The ACME Endpoint never checks these delegations. If DNS points somewhere else, ACME validation fails, but no permission is ever granted by DNS.

---

# Tokens for ACME

An ACME client uses an ordinary **Derived Token**, issued with `dnsgate-cli token create`. It needs no new kind of token and no ACME claim:

- a Permission allowing `patch` on TXT records at each Challenge Target it should write;
- an egress that includes the one the ACME Endpoint asks for with `--egress` (or no egress filter at all, which means any egress).

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
  ]
}
```

`resources` is left out of both Permissions, so it defaults to `records`. Claim names are examples.

---

# acme-dns API

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
- **`subdomain`** is a single DNS label or a domain name. A key in the Challenge Map names its Challenge Target; anything else is taken as the Certificate Domain.
- **`txt`** must be exactly 43 characters of `[A-Za-z0-9_-]` (unpadded base64url of a SHA-256 digest). Anything else is rejected, so an ACME token sent through the ACME Endpoint can't write arbitrary TXT values.

The request body is capped at 4 KiB.

## How `/update` maps to Gateway calls

First, checks done locally, before any Gateway call:

```text
parse the JSON body                         → 401 forbidden if malformed or over 4 KiB
subdomain a DNS label or a domain name?     → 400 bad_subdomain
txt is 43 chars of [A-Za-z0-9_-]?           → 400 bad_txt
Challenge Map[subdomain] → Challenge Target, else _acme-challenge.<subdomain>
X-Api-Key present?                          → 401 forbidden if empty
```

A body that is not exactly one JSON object (trailing data included) is malformed, and so is a body over 4 KiB, which is cut off before it is decoded.

Then two Gateway calls, both with the caller's `X-Api-Key` as the Service Token, unchanged:

1. **`InspectToken`** returns the token's `jti`, which must equal `X-Api-User`. A failed inspect (bad, expired or revoked token) or a mismatch returns 401.
2. **`PatchRecord`** adds the value at the Challenge Target:

   ```text
   token:  X-Api-Key
   egress: --egress
   zone:   Challenge Target zone
   name:   Challenge Target name
   type:   TXT
   ttl:    --ttl
   add:    ["\"<txt>\""]     (TXT presentation form)
   ```

   The Gateway checks Revocation, Permissions (`patch` on TXT at the Challenge Target) and Egress, then writes through the Provider. A value already present is a no-op in `patch`, so a retry returns 200 again.

## Error mapping

The Gateway's errors map to the acme-dns response contract:

| Gateway result | Reply |
|---|---|
| Success, including a value already present | 200 `{"txt": "<value>"}` |
| Unauthenticated (bad, expired or revoked token) | 401 `{"error": "forbidden"}` |
| Permission denied by the Gateway, including an Egress the token doesn't allow and a Bound Token presented without an Identity Token | 401 `{"error": "forbidden"}` |
| Permission denied by the Provider (it refused the Provider Credential) | 500 `{"error": "provider_error"}` |
| Invalid argument: the TTL refused (outside the Provider's range) | 500 `{"error": "provider_error"}`, logged as a configuration error |
| Provider failure, including rate limiting | 500 `{"error": "provider_error"}` |
| Gateway unreachable or timed out | 500 `{"error": "provider_error"}` |

Details of a 500 go only to the ACME Endpoint's log, never to the client.

## Response contract

Clients depend on these exact status codes and bodies:

| Case | Status | Body |
|---|---|---|
| Success, including a value that already exists | **200** (exactly; certbot and Caddy require it) | `{"txt": "<value>"}`. acme.sh looks for the value in the body. |
| Any authentication or authorization failure: missing, bad, expired or revoked token, `X-Api-User` mismatch, no zone of the token for the Challenge Target, Permission missing, egress not allowed, Bound Token, malformed JSON, a body over 4 KiB | 401 | `{"error": "forbidden"}` |
| `subdomain` is neither a DNS label nor a domain name | 400 | `{"error": "bad_subdomain"}` |
| `txt` has the wrong shape | 400 | `{"error": "bad_txt"}` |
| Provider failure, including the Provider refusing the Provider Credential (a permission denied that is not a 401), TTL refused, Gateway unreachable | 500 | `{"error": "provider_error"}` (details go to the log only) |

## `GET /health`

Returns 200 with an empty body.

## `POST /register`

**Not supported** (404). Tokens are provisioned statically by an Administrator. Clients that register automatically when they have no credentials (acme.sh, lego, the acme-dns-auth certbot hook) must be given credentials in advance.

---

# acmeproxy API

The acmeproxy API is the HTTP "present / cleanup" protocol in its default (non-RAW) mode. It is served on the same listener, TLS settings, body cap and timeouts as the acme-dns API, at the root path. A client that expects a path prefix gets it from a reverse proxy in front of the ACME Endpoint. RAW mode (`{"domain", "token", "keyAuth"}`) is not supported.

## `POST /present` and `POST /cleanup`

Request:

```http
POST /present
Authorization: Basic base64(tok_01JACME...:<Service Token>)
Content-Type: application/json

{"fqdn": "_acme-challenge.www.example.com.", "value": "<43-char base64url challenge value>"}
```

`POST /cleanup` takes the same body.

- **Basic auth**: the username is the token's `jti` and the password is the full Service Token, the pair an acme-dns client sends as `X-Api-User` and `X-Api-Key`. A username that is not the token's `jti` returns 401, as for `X-Api-User`. Every acmeproxy client takes its username and password this way.
- **`fqdn`** is the Challenge Target, an absolute name: the trailing dot is optional and case is ignored. It must be at most 253 characters, have at least two labels, and each label must be a DNS label (leading underscores allowed, as in `_acme-challenge`). A single label is refused, never read as relative. It need not start with `_acme-challenge`: clients that follow CNAMEs (lego does by default) send the delegated target, such as `challenge-123.acme.example.net.`, so the token's Permissions must allow `patch` on TXT at that name.
- **`value`** must be exactly 43 characters of `[A-Za-z0-9_-]`, the same check as `txt` in `/update`.

Unknown fields are ignored. The body must be exactly one JSON object, with nothing after it, and at most 4 KiB, as for `/update`.

## How the calls map to Gateway calls

The **Challenge Map is not consulted.** The zone of the `fqdn` is the longest zone named in the token's Permissions that holds the name and allows `patch` on TXT there, so the Administrator configures no zone per domain. An `fqdn` in no such zone is refused with 401 `forbidden`, without a write.

Local checks come first (JSON, `fqdn`, `value`, Basic auth present), then the same two Gateway calls as `/update`, with the Basic auth password as the Service Token, unchanged:

1. **`InspectToken`** returns the token's `jti`, which must equal the Basic auth username, and the Permissions the zone is taken from.
2. **`PatchRecord`** on TXT at the Challenge Target, with the `--egress` Egress:
   - `/present` adds the value (`add: ["\"<value>\""]`, `ttl: --ttl`). A value already present is kept once, and a second value at the same name sits next to the first, so the apex and wildcard challenges of one certificate validate together.
   - `/cleanup` removes that value only (`remove: ["\"<value>\""]`, no TTL). Every other value at the Challenge Target stays, so a cleanup never breaks a validation still running. Removing a value that is not there, even at a name with no TXT records at all, succeeds.

## Response contract

| Case | Status | Body |
|---|---|---|
| Success, including a value already present (`/present`) or already absent (`/cleanup`) | 200 | The request echoed: `{"fqdn": "...", "value": "..."}`. acme.sh looks for the value in the body; libdns checks both fields. |
| No Basic auth, or an empty password | 401 | `{"error": "forbidden"}` |
| Username is not the token's `jti` | 401 | `{"error": "forbidden"}` |
| Token refused by the Gateway (bad, expired, revoked, Bound Token) | 401 | `{"error": "forbidden"}` |
| Permission or Egress refused by the Gateway | 401 | `{"error": "forbidden"}` |
| `fqdn` in no zone of the token's Permissions | 401 | `{"error": "forbidden"}` |
| Malformed JSON, data after the JSON object, or a body over 4 KiB | 400 | `{"error": "bad_request"}` |
| `fqdn` is not a valid name (single label, too long, bad label) | 400 | `{"error": "bad_fqdn"}` |
| `value` is not a DNS-01 challenge value | 400 | `{"error": "bad_value"}` |
| Provider failure, the Provider refusing the Provider Credential, TTL refused, Gateway unreachable or timed out | 500 | `{"error": "provider_error"}` (details go to the log only) |

Gateway errors map to replies exactly as for `/update`. Only a malformed or oversized body differs: the acme-dns API answers it 401 `forbidden`, the acmeproxy API 400 `bad_request`. Clients look only at the status: lego treats any non-2xx status as a failure, libdns any status but 200.

## Tokens for acmeproxy clients

An acmeproxy client uses an ordinary narrow ACME token. Because the client names the Challenge Target, limit the token's Permissions by name, not only by zone: `patch` on TXT at `_acme-challenge` names plus any delegated names, a mandatory expiry, and no `tokens` resource. The same minimal token suits acme-dns clients. `/cleanup` needs no extra verb, since `patch` covers removal. [permissions-acme.yaml](permissions-acme.yaml) is a minimal Permissions file:

```yaml
permissions:
  - verbs: [patch]
    resources: [records]
    zones: ["example.com"]
    names: ["_acme-challenge", "_acme-challenge.**"]
    types: [TXT]
    egress: [gateway, agent]
```

Add a Permission for each delegated Challenge Target, for example `zones: ["example.net"]` with `names: ["challenge-123.acme"]`, and drop the egress the ACME Endpoint does not ask for. Issue it with an expiry:

```sh
dnsgate-cli token create --sub traefik-prod --permissions docs/permissions-acme.yaml --expires 2160h
```

The client is given the token and its `jti`.

## Client configuration

In every client, the endpoint is the ACME Endpoint's URL, and the username and password are set as in [Basic auth](#post-present-and-post-cleanup). Reach the ACME Endpoint over HTTPS (directly, or through a TLS-terminating proxy), since the Service Token travels in the `Authorization` header.

### lego `httpreq`

```sh
HTTPREQ_ENDPOINT=https://acme.gateway.example \
HTTPREQ_USERNAME=tok_01JACME... \
HTTPREQ_PASSWORD=<Service Token> \
lego run --dns httpreq -d '*.example.com' -d example.com
```

Leave `HTTPREQ_MODE` unset (default mode; `RAW` is not supported). lego follows CNAMEs by default; see [`fqdn`](#post-present-and-post-cleanup).

### Traefik

Traefik uses lego's `httpreq` provider, configured by the same environment variables on the Traefik process:

```yaml
certificatesResolvers:
  gateway:
    acme:
      email: admin@example.com
      storage: acme.json
      dnsChallenge:
        provider: httpreq
```

```sh
HTTPREQ_ENDPOINT=https://acme.gateway.example
HTTPREQ_USERNAME=tok_01JACME...
HTTPREQ_PASSWORD=<Service Token>
```

### acme.sh `dns_acmeproxy`

```sh
export ACMEPROXY_ENDPOINT=https://acme.gateway.example
export ACMEPROXY_USERNAME=tok_01JACME...
export ACMEPROXY_PASSWORD=<Service Token>
acme.sh --issue --dns dns_acmeproxy -d example.com -d '*.example.com'
```

acme.sh saves the three settings in the account configuration on the first run. It sends `fqdn` with a trailing dot and checks that the reply contains the value.

### Caddy / libdns `acmeproxy`

Build Caddy with the `github.com/caddy-dns/acmeproxy` module, then:

```caddyfile
example.com {
	tls {
		dns acmeproxy https://acme.gateway.example {
			username {env.ACMEPROXY_USERNAME}
			password {env.ACMEPROXY_PASSWORD}
		}
	}
}
```

or in JSON, as the `acme` issuer's `challenges.dns.provider`:

```json
{
  "name": "acmeproxy",
  "endpoint": "https://acme.gateway.example",
  "username": "tok_01JACME...",
  "password": "<Service Token>"
}
```

The module expands placeholders in all three settings, so the token can come from the environment. libdns requires exactly 200 and checks that the reply echoes `fqdn` and `value`.

---

# HTTP and HTTPS

- With `--tls-cert-file` and `--tls-key-file`, `dnsgate-acme` serves **HTTPS**, TLS 1.2 or later, since some ACME clients and Proxmox run older TLS stacks.
- With neither, it serves **plain HTTP**, for use behind a TLS-terminating proxy or Kubernetes ingress. ACME clients must still reach that proxy over HTTPS: the Service Token travels in `X-Api-Key` or in the Basic auth `Authorization` header.
- With only one of the two, it stops at startup.

Read, write and idle timeouts are bounded. The daemon shuts down cleanly on SIGINT or SIGTERM.

---

# Cleanup

The ACME Endpoint removes a challenge value **only when a client asks**, through the acmeproxy `/cleanup` ([ADR 0013](adr/0013-acme-endpoint-speaks-acmeproxy-and-cleans-up-on-request.md)). It never deletes or prunes on its own: no timer, no rule based on age or count.

- **acmeproxy clients** call `/cleanup` once validation is done. It removes exactly the value named, inside the request and with the caller's token, so nothing is kept after the request and no other validation at the same Challenge Target is touched.
- **acme-dns clients** never ask for removal: their cleanup step does nothing, and the acme-dns API has no removal call. Deleting later on their behalf would need the Service Token after the request is over, which the ACME Endpoint does not keep, and pruning by count can race with another validation still running at a shared Challenge Target.

Consequences:

- Values written through `/update` pile up at each Challenge Target, roughly two per renewal plus retries. Values written through `/present` remain only when a client fails before its `/cleanup`. The Administrator removes leftovers with `dnsgate-cli record patch --remove` or `dnsgate-cli record delete`.
- There is **no limit** on how many values a Challenge Target can hold. Enforcing one would need the RRset, and a `patch`-only token can't read it ([ADR 0011](adr/0011-acme-endpoint-is-a-gateway-client.md)). A client stuck in a retry loop keeps adding values until someone cleans up.

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
| lego `httpreq` (acmeproxy) | `HTTPREQ_ENDPOINT`, `HTTPREQ_USERNAME`, `HTTPREQ_PASSWORD` | Any 2xx is success. |
| Traefik (acmeproxy) | `dnsChallenge.provider: httpreq`, plus lego's `HTTPREQ_*` variables | Built on lego `httpreq`. |
| acme.sh `dns_acmeproxy` | `ACMEPROXY_ENDPOINT`, `ACMEPROXY_USERNAME`, `ACMEPROXY_PASSWORD` | Looks for the value in the reply. |
| Caddy `caddy-dns/acmeproxy` | endpoint, `username`, `password` | Requires exactly 200 and the request echoed. |

The account fields map the same way for every acme-dns client:

```text
username   = token jti
password   = Service Token
subdomain  = a key in the ACME Endpoint's Challenge Map, or the Certificate Domain
fulldomain = the Challenge Target (used by the client only to print the CNAME to create)
```

acmeproxy clients take the token as their username and password, as in [Basic auth](#post-present-and-post-cleanup).

---

# Security Notes

- **An ACME token presented straight to the Gateway skips the TXT shape check.** The 43-character check runs only in the ACME Endpoint, for both APIs. Anyone holding an ACME token can call `PatchRecord` on the Gateway directly and add any TXT value its Permissions allow, such as an SPF record or a domain verification string. Keep ACME tokens narrow, as in [Tokens for acmeproxy clients](#tokens-for-acmeproxy-clients).
- **Expect ACME tokens to leak into logs.** Some clients print `X-Api-Key` when an update fails.
- **An acmeproxy client names its own Challenge Target.** The `fqdn` can be any name the token's Permissions allow, so limit the token's Permissions by name, not only by zone ([Tokens for acmeproxy clients](#tokens-for-acmeproxy-clients)).
- **The certificate domain is not sent as such**, only the subdomain (or `fqdn`) and the value. A client may put the domain in the subdomain field, and the ACME Endpoint then writes at `_acme-challenge` in front of it, but nothing proves that is the domain of the certificate being issued. Authorization is therefore by Challenge Target only.
- **Checking the value's shape** stops the token, when used through the ACME Endpoint, from writing arbitrary TXT values. It doesn't prove the caller holds a real ACME authorization.
- **The ACME Endpoint holds no keys.** Compromising it exposes the tokens presented to it while compromised, and lets it rewrite the Challenge Map, but not the Gateway's keys, so it cannot open or mint tokens, and the Gateway still limits every write by the token's Permissions.

---

# Logging

The ACME Endpoint logs each `/update` (successful or refused) as a structured event, `"msg": "update"`, with `request_id` (`req_` and a ULID), `subdomain`, the Challenge Target (`zone` and `name`), `result` (`ok` or the error, such as `forbidden`) and `duration_ms`. A `reason` is added to every 401 and 500 and to nothing else: a malformed body, no `X-Api-Key`, an `X-Api-User` that is not the `jti`, no zone of the token for the Challenge Target, or a Gateway call refused or failed. A `bad_subdomain` or `bad_txt` refusal has no `reason`. The Gateway's `error` is added only when a Gateway call is refused or fails. Successes and refusals are logged at info, failures (500) at error. A subdomain that is neither a DNS label nor a domain name is left out, since it may hold anything.

Each acmeproxy request is logged the same way, `"msg": "acmeproxy"`, with `request_id`, `action` (`present` or `cleanup`), `fqdn` (only once it is a valid name), `zone`, `name`, `result` and `duration_ms`. A `reason` is added to a malformed body (here a 400 `bad_request`) and to every 401 and 500, with the same `reason` as `/update` for the same cause; a request without Basic auth is logged with `no Basic auth`. A `bad_fqdn` or `bad_value` refusal has no `reason`. The Gateway's `error` is added only when a Gateway call is refused or fails.

At the `debug` log level, each request also logs its request headers, `"msg": "update headers"` or `"msg": "acmeproxy headers"`, with the same `request_id`. The values of `X-Api-Key`, `Authorization`, `Proxy-Authorization` and `Cookie` are replaced by their length.

Never logged: the Service Token, `X-Api-Key`, `Authorization`, the TXT value.

The Gateway's audit log records every ACME write as a `patch` by the token's Service Account, like any other write.

---

# v2 Scope

1. `dnsgate-acme` with `POST /update`, `POST /present`, `POST /cleanup`, `GET /health` and `POST /register` (404), over HTTP or HTTPS
2. The optional Challenge Map file, checked at startup
3. Each `/update`, `/present` and `/cleanup` as InspectToken plus PatchRecord, with the TXT value shape check
4. Gateway Egress and Agent Egress, chosen with `--egress`
5. The response contracts above
6. Integration tests against acme.sh, lego and cert-manager

Not planned: `/register`, acmeproxy RAW mode, cleanup through the acme-dns API, automatic cleanup, a per-target value limit, DNS or CNAME discovery, checking delegations, Bound Tokens.
