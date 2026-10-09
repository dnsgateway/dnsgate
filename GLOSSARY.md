# DNS Gateway

A security layer between applications and DNS provider APIs. It lets each application manage only the DNS records it is permitted to, without ever handing it the provider's credential.

## Language

### Components

**Gateway**:
The service that authorizes DNS requests and executes them against DNS providers on a client's behalf.
_Avoid_: Router, DNS Router, proxy

**ACME Endpoint**:
The part of the Gateway that speaks the acme-dns HTTPS API, so existing ACME clients can write DNS-01 challenge values.
_Avoid_: acme-dns server, ACME handler, compatibility API

**Egress Agent**:
The role a client plays when it relays the Gateway's encrypted TCP connection to a DNS provider, so the provider sees the client's source IP.
_Avoid_: Client Agent, relay, proxy

**Provider**:
A DNS service whose API the Gateway calls on a client's behalf, such as Cloudflare.
_Avoid_: backend, upstream, DNS host

### Identities

**Administrator**:
A person who onboards Provider Credentials into the Gateway and holds tokens that may issue other tokens.
_Avoid_: admin user, operator, owner

**Service Account**:
The name of the application or workload a Service Token was issued for. It is a label carried in tokens, not a record the Gateway keeps. It is not a Kubernetes ServiceAccount: that is part of an Identity Token, verified by its issuer.
_Avoid_: user, client, principal

**Trusted Issuer**:
An OIDC issuer the Gateway is configured to accept Identity Tokens from. Each one is a trust root: whoever controls it can prove any identity it issues.
_Avoid_: IdP, identity provider, OIDC provider

**Identity Token**:
A short-lived OIDC token from a Trusted Issuer that a workload presents alongside a Bound Token, proving who the workload is, such as a Kubernetes ServiceAccount, a GitHub Actions job or a GitLab CI job.
_Avoid_: JWT, OIDC token, SA token, principal

### Credentials

**Service Token**:
The opaque, encrypted credential a client presents to the Gateway; it carries everything needed to authorize and execute its requests.
_Avoid_: API key, JWT, access token

**Root Token**:
The first Service Token for a provider account, created when an Administrator onboards its Provider Credential.
_Avoid_: admin token, master token

**Derived Token**:
A Service Token issued by presenting another Service Token whose permissions allow issuing.
_Avoid_: child token, sub-token

**Parent Token**:
The Service Token that was presented to issue a Derived Token.
_Avoid_: issuer token, source token

**Onboarding**:
Turning a plaintext Provider Credential into a Root Token; the only moment the Provider Credential is handled in plaintext outside the Gateway.
_Avoid_: import, registration, sealing

**Bootstrap Secret**:
The secret configured on the Gateway that authorizes Onboarding. It is the only credential the Gateway checks that is not a Service Token, and it grants nothing else.
_Avoid_: admin password, master secret, setup token

**Permission**:
A rule inside a Service Token that grants verbs on zones, records or tokens, limited to certain zones, record name patterns, record types and Egress. Permissions only add up; there is no deny.
_Avoid_: policy, role, capability, scope

**Narrowing**:
The rule that a Derived Token's permissions and expiry never exceed its Parent Token's, and that it keeps the Parent Token's Identity Binding.
_Avoid_: attenuation, scoping down

**Identity Binding**:
The requirement inside a Service Token naming one Trusted Issuer and the exact claim values an Identity Token must carry. It is part of Narrowing: a Derived Token keeps its Parent Token's binding and may only add claims to it.
_Avoid_: principal, identity restriction, binding policy

**Bound Token**:
A Service Token that carries an Identity Binding, so it is usable only together with a matching Identity Token.
_Avoid_: OIDC token, workload token

**Revocation**:
Permanently invalidating a Service Token and every token derived from it.
_Avoid_: untrust, disabling, deletion

**Resealing**:
Re-encrypting an existing Service Token under the Gateway's current key, without changing its identity or permissions.
_Avoid_: token rotation, refresh, re-issue

**Decryption Key**:
An older Gateway encryption key, kept after a rotation only to open Service Tokens sealed under it until they are Resealed. No token is ever sealed under it.
_Avoid_: old key, legacy key, previous key

**Retirement Deadline**:
The time from which a Decryption Key opens no Service Token. A token not Resealed by then stops working.
_Avoid_: expiry, key expiration, grace period

**Provider Credential**:
The secret that authenticates to a Provider's API. Every Service Token is bound to exactly one. Clients never see it in plaintext.
_Avoid_: master key, provider token, API key, provider account

### Records

**RRset**:
Every record of one name and type in a zone. It is what the record verbs act on: `create`, `update` and `delete` take a whole RRset, `patch` single values inside one.
_Avoid_: record set, record group, record

**Changeset**:
The changes (add, modify, delete) to one zone's records that the Gateway applies through the Provider to carry out one record verb. A Provider that confirms each change on its own may make some of them and fail others.
_Avoid_: batch, transaction, diff, patch

### ACME

**Challenge Target**:
The TXT record name where an ACME DNS-01 challenge value is written.
_Avoid_: update target, validation name, challenge record

**Challenge Map**:
The mapping inside a Service Token from acme-dns subdomain to Challenge Target. It grants nothing on its own: every Challenge Target must also be covered by the token's Permissions.
_Avoid_: ACME accounts, subdomain list

### Egress

**Egress**:
The point from which the TCP connection to a DNS provider leaves, as seen by the provider.
_Avoid_: direct, proxy, mode

**Gateway Egress**:
Egress from the Gateway's own infrastructure, including the ACME Endpoint; the provider sees the Gateway's source IP.
_Avoid_: router egress, direct

**Agent Egress**:
Egress through an Egress Agent; the provider sees the client's source IP.
_Avoid_: client egress, proxy
