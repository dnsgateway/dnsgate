# DNS Gateway — Workload Identity (v2)

## Goal

Let a Service Token be usable only by one specific workload, proven by that workload's OIDC identity. A leaked token alone is then useless.

Supported platforms in v2:

- Kubernetes workloads (projected ServiceAccount tokens)
- GitHub Actions
- GitLab CI

All three use the same mechanism. Platform knowledge lives only in the CLI, which turns platform-specific flags into an Identity Binding.

This document builds on the core architecture in [draft.md](draft.md). Terms are defined in [GLOSSARY.md](../GLOSSARY.md). The decision is recorded in [ADR 0004](adr/0004-identity-binding-in-service-tokens.md). Sequence diagrams are in [oidc-flows.md](oidc-flows.md).

---

# Main Principle

A **Bound Token** is an ordinary Service Token that carries an **Identity Binding**. To use it, the client must also present an **Identity Token** from the named **Trusted Issuer** whose claims match the binding.

```text
Bound Token      → what may be done, and who may do it   (Gateway-signed, opaque to the client)
Identity Token   → who is asking                          (issuer-signed, short-lived)
```

Neither is enough on its own:

| Attacker holds | Result |
|---|---|
| Bound Token only | denied: no matching Identity Token |
| Identity Token only | denied: no Service Token, no Provider Credential |
| Both | allowed within the token's Permissions until the Identity Token expires |

Identity Binding is optional. A Service Token without one behaves exactly as in v1.

OIDC does not replace or carry the Provider Credential. The Provider Credential stays inside the Service Token, as in [ADR 0001](adr/0001-self-contained-service-tokens.md).

---

# Identity Binding

## Claim

The binding is a claim inside the signed and encrypted Service Token. Claim names are examples; the exact schema will be fixed during implementation.

```json
{
  "sub": "external-dns-prod",
  "jti": "tok_01JK8S...",
  "ancestors": ["tok_01JROOT..."],
  "provider": "cloudflare",
  "credential": { "type": "api-token", "value": "..." },
  "permissions": [ ... ],

  "identity": {
    "issuer": "https://cluster-prod.example",
    "claims": {
      "sub": "system:serviceaccount:dns:external-dns"
    }
  }
}
```

## Matching

- `iss` of the Identity Token must equal `identity.issuer` exactly.
- Every entry in `identity.claims` must be present in the Identity Token with exactly that value. All entries must match (AND).
- Claims with an array value (such as `aud`) cannot be bound.
- Non-string claim values are compared by their JSON form, so `true` matches the binding value `"true"`.
- One binding per token. No globs, no regular expressions, no alternatives. A workload that runs in two clusters gets two tokens.

## Service Account label

The token's `sub` (the Service Account) stays a free-form label set by whoever issues the token. It is independent of the binding:

- The **Service Account** says what the token was *issued for*, for example `external-dns-prod`.
- The **Identity Token** says who actually *used* it, for example `system:serviceaccount:dns:external-dns`.

These usually differ, and both appear in audit events. A binding often doesn't pin everything (a GitHub binding on a repository and environment still admits any workflow and ref in that environment), so the Identity Token's own `sub` is what shows which job made the request.

## Narrowing

The Identity Binding is a Narrowing dimension:

- An unbound Parent Token may issue a Bound Token. Adding a binding is narrower.
- A Derived Token of a Bound Token must keep the same issuer and every required claim. It may add more claims.
- A Bound Token can never issue an unbound token, or a token bound to a different issuer.
- Issuing a Derived Token from a Bound Parent Token requires the parent's Identity Token, like any other use of it.

The usual setup: an Administrator holds an unbound Root or intermediate token and issues one Bound Token per workload.

---

# Trusted Issuers

The Gateway accepts Identity Tokens only from issuers listed in its configuration. Each Trusted Issuer is a trust root: whoever controls it can satisfy any binding to it.

```yaml
identity:
  audience: https://gateway.example        # default for all issuers
  issuers:
    - issuer: https://token.actions.githubusercontent.com

    - issuer: https://gitlab.com

    - issuer: https://cluster-prod.example
      jwks_file: /etc/dnsgate/jwks/cluster-prod.json
      audience: dnsgate-prod               # per-issuer override
      max_lifetime: 1h
```

- **Issuance:** the Gateway refuses to issue a Bound Token whose `identity.issuer` is not configured.
- **Every request:** the issuer must still be configured. Removing an issuer immediately disables every Bound Token that names it.
- **Uniqueness:** issuer values must be unique. Duplicate issuers are a startup error. Each Kubernetes cluster therefore needs its own `--service-account-issuer` URL; many clusters default to `https://kubernetes.default.svc`, which cannot tell clusters apart.
- The issuer list is Gateway configuration, not token data. Token holders can never make the Gateway trust a new issuer or fetch a URL of their choice.

## Audience

The Identity Token's `aud` must contain the configured audience: the Gateway-wide default, or the issuer's override. A token minted for any other service is rejected. Audience is not part of the binding.

## Signing keys

- **Default:** OIDC discovery. The Gateway fetches `<issuer>/.well-known/openid-configuration`, checks that its `issuer` equals the configured value, and reads `jwks_uri`.
- **Override:** `jwks_uri` (fetched directly) or `jwks_file` (a static JWKS on disk). Use this for Kubernetes clusters whose issuer is not publicly reachable.
- HTTPS only. Discovery and JWKS URLs come only from configuration, never from an incoming token.
- Keys are cached. An unknown `kid` triggers a refetch, rate-limited per issuer.
- Asymmetric algorithms only (RS256, ES256 and similar). `none` and HMAC algorithms are rejected.

Kubernetes TokenReview is not supported in v2.

## Lifetime

Each Trusted Issuer has a maximum Identity Token lifetime (`exp - iat`), 1h by default. Longer-lived tokens are rejected. `exp`, `nbf` and `iat` are checked with 60s of clock skew.

Typical lifetimes: Kubernetes projected tokens default to 1h. GitHub Actions and GitLab CI tokens last minutes.

---

# Request Flow

The Identity Token travels in gRPC stream metadata:

```text
authorization: Bearer <Identity Token>
```

It is checked once per stream, after the Service Token is verified and before Permissions are evaluated:

```text
receive request
  ↓
decrypt and verify the Service Token, check iss / aud / nbf / exp
  ↓
check jti and ancestors against revoked IDs
  ↓
if the token has an Identity Binding:
    issuer configured? → verify Identity Token signature, iss, aud, exp, nbf, lifetime
    → match binding claims
  ↓
check Permissions, egress
  ↓
use the Provider Credential
```

A missing or non-matching Identity Token is rejected with the same error as an invalid Service Token. The response does not say which check failed.

## Which operations need it

| Operation with a Bound Token | Identity Token |
|---|---|
| record operations | required |
| `token create` (Bound Parent) | required |
| `token revoke` | required |
| `token inspect` | required |
| `token reseal` | not required: resealing uses neither the Permissions nor the Provider Credential, and is usually done by an Administrator who doesn't hold the workload's identity |

## ACME Endpoint

acme-dns clients cannot send an Identity Token. The [ACME Endpoint](acme.md) rejects Bound Tokens.

---

# Platforms

The CLI has presets that build an Identity Binding. Presets bind on **immutable IDs** where the platform has them, because names can be reused: a deleted repository or project can be recreated under the same name by someone else, and GitHub repository owners can customise `sub`.

## Kubernetes

Binding: issuer + `sub`. The issuer identifies the cluster, so namespace and ServiceAccount name are enough.

```text
dnsgate-cli token create --sub external-dns-prod --permissions external-dns.yaml \
    --bind-k8s --issuer https://cluster-prod.example --service-account dns/external-dns
```

```json
"identity": {
  "issuer": "https://cluster-prod.example",
  "claims": { "sub": "system:serviceaccount:dns:external-dns" }
}
```

The Pod receives the Identity Token as a projected volume with the Gateway's audience, and the Bound Token as an ordinary Secret. The Bound Token is ciphertext, so storing it in a Secret is safe.

```yaml
spec:
  serviceAccountName: external-dns
  volumes:
    - name: dnsgate
      projected:
        sources:
          - serviceAccountToken:
              path: identity.jwt
              audience: https://gateway.example
              expirationSeconds: 3600
          - secret:
              name: dnsgate-token
              items:
                - key: token
                  path: service.token
```

The kubelet rotates `identity.jwt`. The CLI re-reads it for every request.

## GitHub Actions

Binding: issuer + `repository_id` + `repository_owner_id`, with optional `ref` and `environment`.

```text
dnsgate-cli token create --sub infra-dns-prod --permissions infra.yaml \
    --bind-github --repository-id 123456 --owner-id 7890 --environment production
```

```json
"identity": {
  "issuer": "https://token.actions.githubusercontent.com",
  "claims": {
    "repository_id": "123456",
    "repository_owner_id": "7890",
    "environment": "production"
  }
}
```

The CLI accepts a repository name (`--repository acme/infra`) and resolves it to IDs at issuance.

In the workflow, the job needs `permissions: id-token: write`. The CLI fetches the Identity Token itself with `--identity-token-source github-actions`, using `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and the configured audience.

## GitLab CI

Binding: issuer + `project_id` + `namespace_id`, with optional `ref`, `ref_protected` and `environment`.

```text
dnsgate-cli token create --sub gitlab-infra-main --permissions infra.yaml \
    --bind-gitlab --project-id 42 --namespace-id 7 --ref main --ref-protected
```

```json
"identity": {
  "issuer": "https://gitlab.com",
  "claims": {
    "project_id": "42",
    "namespace_id": "7",
    "ref": "main",
    "ref_protected": "true"
  }
}
```

Self-managed GitLab uses its own URL as the issuer.

```yaml
deploy-dns:
  id_tokens:
    DNSGATE_IDENTITY_TOKEN:
      aud: https://gateway.example
  script:
    - dnsgate-cli record update ... --identity-token-env DNSGATE_IDENTITY_TOKEN
```

## CLI options

| Option | Use |
|---|---|
| `--identity-token-file PATH` | read the Identity Token from a file before every request (Kubernetes) |
| `--identity-token-env NAME` | read it from an environment variable (GitLab CI) |
| `--identity-token-source github-actions` | fetch it from the GitHub Actions token service |

---

# Audit Logging

For a Bound Token, audit events add: Identity Token issuer, Identity Token `sub`, and the values of the bound claims.

Never logged: the raw Identity Token, the `authorization` metadata.

---

# Threat Model

## Leaked Bound Token

Useless without a matching Identity Token from the bound issuer.

## Leaked Identity Token

Useless without the Bound Token. Identity Tokens are short-lived and audience-restricted to the Gateway.

## Both leaked (accepted risk)

The attacker can act within the token's Permissions until the Identity Token expires, or until the Service Token is revoked. There is no proof of possession: Identity Tokens are bearer tokens.

## Same workload name in another cluster

A Pod in another cluster with the same namespace and ServiceAccount has a different issuer, so it doesn't match. This requires unique issuer URLs per cluster.

## Repository or project recreated under the same name

GitHub and GitLab presets bind on immutable IDs, so a new repository with the old name doesn't match.

## Trusted Issuer compromise (accepted risk)

Whoever controls a Trusted Issuer can mint Identity Tokens that satisfy any binding to it. Configure only issuers you trust as roots, and remove an issuer to disable all its Bound Tokens at once.

---

# v2 Scope

1. Identity Binding claim in Service Tokens, checked by Narrowing
2. Trusted Issuer configuration: audience, discovery or `jwks_uri` / `jwks_file`, maximum lifetime
3. Identity Token verification on the gRPC stream
4. Binding enforcement for record and token operations; `token reseal` exempt
5. ACME Endpoint rejects Bound Tokens
6. CLI presets for Kubernetes, GitHub Actions and GitLab CI
7. CLI Identity Token sources: file, environment variable, GitHub Actions
8. Audit fields for identity

# Later

- Kubernetes TokenReview
- Proof of possession (mTLS-bound tokens, DPoP)
- Several bindings per token, globs on claim values
- Other issuers: cloud workload identity, SPIFFE JWT-SVIDs (these may already work as generic issuers, but are not tested or given presets)
