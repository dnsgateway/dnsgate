# Agent Egress relays numbered connections in the request's stream, with half-close and gRPC flow control

For Agent Egress, the Gateway's connections to the Provider are relayed as frames inside the request's own `Call` stream, before its Response. The Gateway sends `RelayOpen{id, host, port}`. The client, as Egress Agent, applies the destination rules (ADR 0002), connects to the address it checked rather than resolving the name again, and answers `RelayOpened{id, error}`. Then both sides send `RelayData{id, data}` (at most 32 KiB each), and each ends its own direction with `RelayClose{id}`, as a TCP FIN. A connection is gone once both sides have closed it, or when the stream ends. The Response is the stream's last message and ends every connection still open. The client keeps its side of the stream open until the Response, so it can relay whichever Egress the Gateway chooses.

Connections carry an id, so one stream can hold several, one after another or at once: the Provider's HTTP transport may open a new connection for a retry, or after the Provider closes one.

Flow control is the stream's own (HTTP/2) flow control. There are no window or acknowledgement frames. Each side writes an incoming frame to its connection before reading the next one: the Gateway into an unbuffered pipe its HTTP transport reads, the Egress Agent into its TCP connection. A slow reader therefore holds back the whole stream. Provider API traffic is small, and a request's connections are mostly used one at a time, so this is accepted.

Timeouts:

- The Gateway waits at most 15 seconds for `RelayOpened`. The Egress Agent's default dialer gives up after 10 seconds.
- Through Agent Egress, the Gateway's Provider transport bounds the TLS handshake (10 seconds) and the wait for response headers (30 seconds), as the Provider's own transport bounds Gateway Egress.
- The Egress Agent gives up on a write to the Provider after 30 seconds and closes that connection.
- Otherwise the relay lives as long as the request: the client cancelling, or the stream ending for any reason, closes every connection on both sides.

The Egress Agent refuses unspecified addresses (`0.0.0.0/8`, `::`) and IPv4-mapped forms of forbidden addresses, as well as the ranges ADR 0002 names. A host that resolves to any forbidden address is refused, even if it also resolves to a public one. The answer to a refused `RelayOpen` says why. The Gateway reports it to the client as a failed Provider request ("the egress agent did not connect to the provider") and never quotes the Egress Agent's text.

## Considered Options

- A stream or connection per relayed connection, outside the request's stream: rejected. The relay has to belong to the connection that presented the token (draft), and a second stream would need its own authorization.
- Window frames for per-connection flow control: rejected for now. They add complexity that only pays off with many connections running at once. They can be added later as new frame kinds in the reserved field numbers.
- Carrying the Provider's HTTP requests instead of TCP bytes: rejected. The client would see the Provider Credential. Relaying TLS bytes keeps it inside the Gateway's TLS session.

## Consequences

- A client that half-closes its side of the stream right after the request cannot act as Egress Agent. A request whose Egress is agent then fails as a failed Provider request.
- Clients and the Gateway both close relayed connections when the stream ends, so a cancelled request leaves no connection or goroutine behind.
- The Gateway verifies the Provider's certificate against the system's CAs. A test or private deployment may name others (`AgentEgressRootCAs`). The Egress Agent cannot weaken this check.
