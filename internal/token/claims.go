// Package token mints and opens Service Tokens (ADR 0001).
//
// A Service Token is JWE(JWS(claims)): the claims are signed with the
// Gateway's Ed25519 signing key (EdDSA, signing kid in the inner header)
// and then encrypted to its X25519 encryption key (ECDH-ES+A256KW /
// A256GCM, typ "dnsgate+jwe" and encryption kid in the outer header).
package token

import "time"

const (
	// Issuer is the iss claim of every Service Token.
	Issuer = "dnsgate"
	// Audience is the aud claim of every Service Token.
	Audience = "dnsgate"
)

// Claims is the content of a Service Token.
//
// The claim names identity (an Identity Binding) and acme (a Challenge
// Map) are reserved for v2. They are not produced, and a token carrying
// them, or any other unknown claim, does not open.
type Claims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	// Subject is the Service Account the token was issued for.
	Subject string `json:"sub"`
	// ID is the token ID (jti), a prefixed ULID such as "tok_...".
	ID        string       `json:"jti"`
	IssuedAt  NumericDate  `json:"iat"`
	NotBefore NumericDate  `json:"nbf"`
	Expiry    *NumericDate `json:"exp,omitempty"`
	// Ancestors lists the IDs of every token above this one, root first.
	Ancestors []string `json:"ancestors,omitzero"`

	// Provider names the Provider the Credential authenticates to.
	Provider   string     `json:"provider"`
	Credential Credential `json:"credential"`

	Permissions []Permission `json:"permissions"`
}

// Credential is the Provider Credential carried in a token. Its Value is a
// Secret, so printing, logging or JSON-encoding a Credential or Claims never
// shows it.
type Credential struct {
	Type  string `json:"type"`
	Value Secret `json:"value"`
}

// Permission is one rule of a token, as carried in its claims. A nil
// filter was left out; an empty one was given as an empty list. Defaulting
// and matching are not this package's concern.
type Permission struct {
	Verbs     []string `json:"verbs,omitzero"`
	Resources []string `json:"resources,omitzero"`
	Zones     []string `json:"zones,omitzero"`
	Names     []string `json:"names,omitzero"`
	Types     []string `json:"types,omitzero"`
	Egress    []string `json:"egress,omitzero"`
}

// NumericDate is a JWT NumericDate: seconds since the Unix epoch.
type NumericDate int64

// NewNumericDate returns t as a NumericDate, dropping sub-second precision.
func NewNumericDate(t time.Time) NumericDate { return NumericDate(t.Unix()) }

// Time returns d as a UTC time.
func (d NumericDate) Time() time.Time { return time.Unix(int64(d), 0).UTC() }
