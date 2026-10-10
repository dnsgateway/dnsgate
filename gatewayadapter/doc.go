// Package gatewayadapter is the Gateway Adapter: it presents the Gateway
// to DNS tools built on the shared Provider interface
// (github.com/dnsgateway/dnsprovider), such as dnscli, so that they manage
// records through the Gateway as they would through a Provider. The
// Gateway itself is never a Provider (ADR 0008).
//
// A Provider the Factory builds holds a Gateway address and a Service
// Token, and sends every call as one Gateway request authorized by that
// token, acting as Egress Agent when the Gateway relays through Agent
// Egress. Zones have their name as ID. Each value of an RRset is one
// Record, with the RRset's TTL, its own Record Extras and an ID built from
// its content. Writes go through ApplyChangeset, which writes each RRset
// a Changeset touches whole, with create, update or delete, and names the
// Expected RRset on each update and delete.
//
// The Provider's TTL range, automatic TTL and Record Extras are those of
// the token's Provider type, which the Gateway names on InspectToken.
//
// A Bound Token is not usable: the Gateway Adapter sends no Identity
// Token.
package gatewayadapter
