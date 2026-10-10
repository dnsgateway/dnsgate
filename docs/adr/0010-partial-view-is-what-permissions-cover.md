# A Partial View says what the Permissions cover, not what was left out

List results now say when they are a Partial View, so a client such as dnscli does not judge a subset as the whole zone. The flag is decided by the token's Permissions alone: a zone list is partial when the Permissions do not cover listing every zone, and a zone's RRsets are partial when they do not cover listing every name and type in it, through the Egress of the call. `permission.Covers` decides this, as it does for Narrowing, so rules that cover everything only together count as full. The flag never depends on what the Provider returned, so it tells the token holder nothing beyond its own Permissions, and it stays the same for the token's life.

## Considered Options

- Set the flag only when filtering left something out of this response: rejected. It is exact for one response, but it tells a token limited to, say, `_acme-challenge` that the zone holds other records it cannot see, and it changes as records come and go.
- Send nothing new and let clients work it out from `InspectToken`: rejected. Every client would have to repeat the Gateway's Permission matching.

## Consequences

- `ListZonesResponse` and `ListRecordsResponse` carry `partial`. False means full, which is how older clients and Gateways read it.
- dnsprovider carries it too: `Zones` returns a `ZoneSet` with `Partial`, as `Records` returns a `RecordSet` with `Partial`. A Provider that is not the Gateway Adapter always returns a full view.
- A Partial View with no entries is still possible, and still says nothing about whether anything is hidden.
