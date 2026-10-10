# The Gateway Adapter lives in the dnsgate repo as a public package

DNS tools built on the shared Provider interface (`github.com/dnsgateway/dnsprovider`), such as dnscli, reach the Gateway through the Gateway Adapter. It lives in this repo as `github.com/dnsgateway/dnsgate/gatewayadapter`, the first public Go package outside `api/`. It exports only `Factory`, `New`, `Config` and its field names, and is built on `internal/client`, so the protocol, its Relay and its error mapping have one owner and change together. It writes whole RRsets with `create`, `update` and `delete`, naming the Expected RRset on each `update` and `delete`, and never needs `patch`.

## Considered Options

- In the dnsprovider module, beside the other adapters: rejected. dnsprovider would require dnsgate while dnsgate requires dnsprovider, `internal/client` would have to become public, and `providers.Registry()` would push gRPC onto every dnsprovider consumer, the Gateway included.
- In dnscli: rejected. The protocol would be reimplemented outside the repo that owns it, and Agent Egress would mean copying the Relay or going without it. It would cost dnscli the same dependency on dnsgate.

## Consequences

- dnscli requires `github.com/dnsgateway/dnsgate` and its go version.
- The package is public API: changing `Factory`'s fields or `Config` breaks dnscli.
- Trust in the Gateway's certificate is set once for the process (`WithRootCAs` on `Factory`), not per Account.
