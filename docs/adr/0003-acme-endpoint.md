# The ACME Endpoint is a separate binary that reads tokens and never cleans up

To support existing ACME clients (acme.sh, lego, cert-manager, certbot, Caddy, Proxmox), we add an ACME Endpoint that speaks the acme-dns HTTPS API. It is a separate binary so it can scale on its own, but it does not forward requests to the Gateway. It holds the encryption private key and the signing public key, decrypts and authorizes Service Tokens itself, and calls the Provider directly. It does not hold the signing private key, so it can read tokens but never mint them. ACME needs no new kind of authority. Each acme-dns `/update` becomes a `patch` on a TXT record, authorized by the token's ordinary Permissions. A Challenge Map in the token picks the Challenge Target for each subdomain.

## Considered Options

- Forwarding to the Gateway over gRPC: rejected, because it adds a network hop without avoiding decryption, and it couples the endpoint's scaling to the Gateway.
- A dedicated `acme-dns01` capability: rejected, because ordinary `patch` Permissions on TXT already express "add a single value at one name".
- Automatic cleanup of challenge values: rejected. No acme-dns client ever asks for removal. Scheduled deletion would need the Provider Credential after the request ends, which means either keeping tokens (and so credentials) in memory or storing them in the database, contrary to ADR 0001. Pruning by count can race with validations still in progress.

## Consequences

- Challenge values pile up. Administrators remove them by hand. To stop a looping client from filling the zone, the endpoint refuses new values at a Challenge Target once it reaches a configured maximum.
- The endpoint needs the shared revoked-ID list, so deployments with an ACME Endpoint require PostgreSQL.
- acme-dns clients cannot relay traffic, so the ACME Endpoint supports Gateway Egress only.
- The certificate domain never reaches the server, so authorization is by Challenge Target only. DNS lookups never grant permission.
