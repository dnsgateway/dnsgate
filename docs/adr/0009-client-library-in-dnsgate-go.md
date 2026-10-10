# The protobuf API, the client and the Gateway Adapter live in dnsgate-go, under Apache 2.0

Supersedes [ADR 0008](0008-gateway-adapter-in-dnsgate.md).

The Gateway's protobuf API (`api/dnsgate/v1`), the Gateway client (formerly `internal/client`, with the Egress Agent's Relay) and the Gateway Adapter move to their own module, `github.com/dnsgateway/dnsgate-go`, licensed Apache 2.0, so that other projects can build their own clients to the Gateway without requiring dnsgate, its dependencies and its go version. dnsgate requires dnsgate-go, as it requires dnsprovider. The protocol, its Relay and its error mapping still have one owner: dnsgate-go. The Gateway implements what that owner defines.

The Gateway Adapter no longer reaches into dnsgate's internals. It maps Egress itself, decides whether a token may list zones by the Gateway's rule for that one request, and holds its own default Registry of the Provider types the Gateway supports. `WithProviders` and `Config.Providers` become public, to replace that Registry. The Gateway Adapter's end-to-end tests need a real Gateway, so they stay in dnsgate, as `test/gatewayadapter`. dnsgate-go tests what needs no Gateway.

## Considered Options

- Keep ADR 0008 and relicense `api/` and `gatewayadapter/` under Apache 2.0 in place: rejected. It frees the licence but every client still requires all of dnsgate and its go version.
- Make `internal/permission` public in dnsgate-go for the zone-list check: rejected. It is the Gateway's authorization engine, built on `internal/token`. The Gateway Adapter needs one narrow question of it.

## Consequences

- A change to `gateway.proto` is made and released in dnsgate-go first, then taken up by dnsgate.
- dnscli requires `github.com/dnsgateway/dnsgate-go` in place of `github.com/dnsgateway/dnsgate`.
- The zone-list rule in `gatewayadapter.mayListZones` must follow `permission.Allows` for that request, and the default Registry must follow `internal/provider.Registry`.
- The package is public API: changing `Factory`'s fields or `Config` breaks its users.
