# A subdomain not in the Challenge Map is taken as the Certificate Domain

Amends [ADR 0011](0011-acme-endpoint-is-a-gateway-client.md).

The ACME Endpoint no longer refuses an acme-dns subdomain that is not a key in the Challenge Map. It takes the subdomain as the Certificate Domain and writes at `_acme-challenge` in front of it, in the longest zone of the token's Permissions that holds that name; an unmapped single label writes `_acme-challenge` in the one zone the token allows. Clients such as cert-manager can then send the domain as their subdomain, and one ACME Endpoint serves new domains without a Challenge Map entry for each. The map never granted anything, since the Gateway checks every write against the token's Permissions, so dropping the refusal widens no token: what an ACME token can reach is exactly what its Permissions allow.

## Considered Options

- Keep refusing unmapped subdomains, as ADR 0011 had it: rejected. Every new certificate domain needed a map entry and a restart of the ACME Endpoint, although the entry only restated what the token's Permissions already bound.
- A single catch-all map entry instead of a built-in fallback: rejected. It cannot name a different Challenge Target per domain, since the request carries nothing but the subdomain.

## Consequences

- The Challenge Map no longer limits which Challenge Targets a token reaches through the ACME Endpoint; the token's Permissions do. Keep ACME tokens to `patch` on TXT at `_acme-challenge` names (`names: ["_acme-challenge", "_acme-challenge.**"]`).
- The subdomain field now takes a domain name as well as a single DNS label, so ADR 0011's "the certificate domain never reaches the server" holds only in that nothing proves the domain sent is the one being certified. Authorization stays by Challenge Target.
- A Challenge Map entry without a zone reads its name as relative only when it is a single label, so an absolute name in no zone of the token is refused rather than written into another zone.
