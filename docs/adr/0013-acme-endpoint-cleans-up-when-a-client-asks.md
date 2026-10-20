# The ACME Endpoint also speaks the acmeproxy API and cleans up when a client asks

Amends [ADR 0011](0011-acme-endpoint-is-a-gateway-client.md).

The ACME Endpoint also serves the acmeproxy API, `POST /present` and `POST /cleanup`, on the same listener as the acme-dns API, so lego `httpreq` (and Traefik), acme.sh `dns_acmeproxy` and Caddy / libdns `acmeproxy` get certificates through the Gateway. `/present` adds one challenge value at a Challenge Target and `/cleanup` removes that same value, each as a `patch` on TXT made with the caller's Service Token, unchanged, so the Gateway still does all the authorization. ADRs 0003 and 0011 refused cleanup because no acme-dns client asks for it, scheduled deletion would need the Provider Credential after the request ends, and pruning by count can race with validations still running. Removal of one named value, asked for by the client and done inside its own request with its own token, has none of those problems: nothing is kept after the request, and no other value at the Challenge Target is touched. So the ACME Endpoint now cleans up when, and only when, a client asks.

The client authenticates with HTTP Basic auth: the password is the Service Token and the username must be the token's `jti`, the same pair an acme-dns client sends as `X-Api-Key` / `X-Api-User`, checked by the same rule. The client sends the full Challenge Target name as `fqdn`, so the Challenge Map is not consulted: the zone is the longest zone named in the token's Permissions that holds the name and allows `patch` on TXT there, and a name in no such zone is refused.

## Considered Options

- Keep "no cleanup" for both APIs: rejected. acmeproxy clients do call `/cleanup`, and the reasons against cleanup in ADRs 0003 and 0011 are about removal the ACME Endpoint would start on its own, not removal a client asks for.
- Scheduled, count-based or background cleanup for acme-dns clients: still rejected, for the reasons of ADR 0011.
- Map the `fqdn` through the Challenge Map: rejected. The client already names the Challenge Target, CNAME-following clients send the delegated name, and since ADR 0012 the token's Permissions, not the map, bound what a token reaches.
- A separate listener, path prefix or authentication scheme (bearer token, password file, mTLS): rejected. Basic auth with the `jti` and the Service Token reuses what Administrators already provision for acme-dns clients, and adds no secret the ACME Endpoint has to hold.

## Consequences

- ADR 0011's consequence that challenge values pile up at a Challenge Target now applies only to acme-dns clients. Values written through `/present` are removed by the client's `/cleanup`, unless the client fails before it calls it.
- `/cleanup` needs no new verb: `patch` covers removal, so an ACME token stays `patch` on TXT at `_acme-challenge` names (`names: ["_acme-challenge", "_acme-challenge.**"]`) plus any delegated names, with a mandatory expiry and no `tokens` resource.
- `/cleanup` of a value that is not there succeeds, so retries and double cleanups are harmless.
- The `fqdn` need not start with `_acme-challenge`. What an acmeproxy client can write is exactly what its token's Permissions allow, as for acme-dns since ADR 0012.
- The Basic auth password is the Service Token, so the `Authorization` header is redacted wherever headers are logged.
