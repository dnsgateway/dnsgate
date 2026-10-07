# Workload identity is an optional binding inside the Service Token, checked against Gateway-configured issuers

A Service Token may carry an Identity Binding: one Trusted Issuer and exact claim values that an OIDC Identity Token must match. A Bound Token is usable only together with such an Identity Token, so a leaked token alone is useless. The binding lives in the signed and encrypted token claims, so the Gateway still stores no policies (ADR 0001). The list of Trusted Issuers, with their audiences and signing-key sources, lives in Gateway configuration. A binding may only name a configured issuer. Matching is generic (exact issuer, exact claim values, all required), and platform knowledge (Kubernetes, GitHub Actions, GitLab CI) lives only in CLI presets.

## Considered Options

- A Gateway-side table mapping token IDs or Service Accounts to allowed identities: rejected, because it is the policy store ADR 0001 avoids, and it would need replication across Gateway replicas and the ACME Endpoint.
- Issuer and JWKS URL defined only inside the token: rejected. Anyone allowed to issue tokens could make the Gateway trust any issuer and fetch any URL (SSRF). Issuers are trust roots and belong to whoever operates the Gateway.
- Typed bindings per platform (Kubernetes namespace and ServiceAccount, GitHub repository, and so on), parsed by the Gateway: rejected. Generic exact claim matching covers all three platforms, keeps Narrowing checks simple, and adding a platform needs only a CLI preset.
- Kubernetes TokenReview instead of offline verification: rejected for v2, because it needs API-server reachability and credentials for every cluster.
- Required OIDC for all tokens once configured: rejected, because clients without a workload identity (people at a terminal, acme-dns clients) must keep working.

## Consequences

- The Identity Binding is a Narrowing dimension. A Derived Token keeps its parent's issuer and claims and may only add claims. A Bound Token can never issue an unbound one.
- Removing an issuer from configuration immediately disables every Bound Token naming it.
- Issuer values must be unique, so every Kubernetes cluster needs its own service-account issuer URL.
- acme-dns clients cannot present an Identity Token, so the ACME Endpoint rejects Bound Tokens.
- Bindings are exact and single. Globs and alternatives would make the Narrowing containment check harder, and are deferred.
