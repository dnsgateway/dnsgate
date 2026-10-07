# The Gateway names the Agent Egress destination by hostname and port

For Agent Egress, the Gateway sends the Egress Agent a full hostname and port to connect to. The Egress Agent does not map a provider name to a host from its own allowlist, which is the protocol the original draft preferred. The Egress Agent enforces two limits: the port must be 443, and the hostname must not resolve to a loopback, RFC1918, link-local, CGNAT, IPv6 ULA or cloud metadata (`169.254.169.254`) address. This keeps new Providers addable from the Gateway alone, with no client update.

## Consequences

- A compromised Gateway can make an Egress Agent open TLS connections to *any* public host on port 443, from the client's IP. This includes services that trust that IP through an allowlist. We accept this for now. A client-side hostname allowlist can be added later without changing the token model.
