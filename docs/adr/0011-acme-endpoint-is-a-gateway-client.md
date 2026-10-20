# The ACME Endpoint is a Gateway client that turns each update into Gateway calls and holds no keys

Supersedes [ADR 0003](0003-acme-endpoint.md). Amended by [ADR 0012](0012-unmapped-subdomain-is-the-certificate-domain.md) and [ADR 0013](0013-acme-endpoint-speaks-acmeproxy-and-cleans-up-on-request.md).

The ACME Endpoint is `dnsgate-acme`, a separate daemon that is an ordinary client of the Gateway API. It speaks the acme-dns API to ACME clients and turns each `POST /update` into two Gateway calls made with the caller's Service Token, unchanged: `InspectToken`, to check that `X-Api-User` is the token's `jti`, then `PatchRecord`, adding one TXT value at the Challenge Target. The Gateway does all the authorization: it opens the token, checks Revocation, Permissions and Egress, and writes through the Provider. The ACME Endpoint holds no keys and no database, and never sees a Provider Credential in plaintext. It cannot read the token, so the Challenge Map moves out of the token into the ACME Endpoint's own configuration. The map still grants nothing: the Gateway accepts a write only if the token's Permissions allow `patch` on TXT at that Challenge Target. The Egress it asks for is set with `--egress`, and `agent` makes the ACME Endpoint the Egress Agent, so the Provider sees its IP.

ADR 0003 made the ACME Endpoint a second reader of Service Tokens. We reverse it for three reasons:

- **One owner of authorization.** Opening tokens, Revocation, Permission matching and Egress checks live only in the Gateway, rather than being copied into a second binary that has to change in step with it.
- **No key on the internet-facing host.** The ACME Endpoint is reachable by every ACME client. Under ADR 0003 it held the encryption private key, so compromising it exposed the Provider Credential inside every token ever issued. Now it holds nothing that opens a token.
- **Agent Egress becomes possible.** The ACME Endpoint can relay the Gateway's connection as an Egress Agent, so tokens whose Permissions allow only `agent` egress, and Provider Credentials that allowlist the network the ACME Endpoint runs in, work for ACME.

## Considered Options

- Keep ADR 0003, an ACME Endpoint that reads tokens itself: rejected, for the three reasons above. Its argument against passing each update to the Gateway, that the extra hop does not avoid decryption, no longer holds: the hop moves decryption off the internet-facing host.
- Serve the acme-dns API from the Gateway process: rejected. It would put the acme-dns listener on the host that holds the keys, and tie the ACME Endpoint's scaling and exposure to the Gateway's.
- Keep the Challenge Map in the token and add a Gateway call that resolves a subdomain: rejected. It needs a change to the Gateway API and the token claims for a mapping that grants nothing, and the Administrator who runs the ACME Endpoint already knows the targets.
- A per-target value limit, as in ADR 0003: dropped. Enforcing it needs the RRset at the Challenge Target, which a `patch`-only token cannot read.

## Consequences

- Each `/update` costs two Gateway round trips (InspectToken, then PatchRecord) on top of the client's request. ACME traffic is rare, so this is accepted.
- The Challenge Map lives in the ACME Endpoint's configuration, so one map serves every token sent to that endpoint, and issuing a token no longer says which subdomains it is for. The reserved `acme` token claim stays unused.
- There is no limit on how many challenge values pile up at a Challenge Target. A client stuck in a retry loop can fill it until an Administrator removes values with `dnsgate-cli record patch --remove` or `record delete`.
- The ACME Endpoint needs no PostgreSQL and no shared state, so several can run behind a load balancer.
- The Gateway's audit log records every ACME write as a `patch` by the token's Service Account, like any other write.
- An ACME token can also be presented straight to the Gateway, where the check on the TXT value's shape does not apply. ACME tokens stay narrow: `patch` on TXT at the Challenge Targets only, no `tokens` resource, and a mandatory expiry.
- Still true from ADR 0003: no `/register`, no cleanup (until ADR 0013, for acmeproxy clients that ask for it), no DNS lookups, and authorization by Challenge Target only, because the certificate domain never reaches the server.
