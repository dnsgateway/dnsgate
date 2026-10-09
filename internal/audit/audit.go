// Package audit writes the Gateway's audit events as JSON lines.
//
// An Event has a fixed set of fields, and nothing else is ever written:
// that field allowlist is what keeps Provider Credentials, Service Tokens
// and bootstrap secrets out of the audit log. Callers fill only values the
// Gateway itself produced or validated.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Name names what an Event records.
type Name string

// Event names.
const (
	EventOnboard       Name = "onboard"
	EventTokenCreate   Name = "token.create"
	EventTokenInspect  Name = "token.inspect"
	EventTokenReseal   Name = "token.reseal"
	EventZonesList     Name = "zones.list"
	EventZonesGet      Name = "zones.get"
	EventRecordsList   Name = "records.list"
	EventRecordsGet    Name = "records.get"
	EventRecordsCreate Name = "records.create"
	EventRecordsUpdate Name = "records.update"
	EventRecordsPatch  Name = "records.patch"
	EventRecordsDelete Name = "records.delete"
)

// Result is the outcome of the request an Event records.
type Result string

// Results.
const (
	ResultOK     Result = "ok"
	ResultDenied Result = "denied"
	// ResultFailed is a request the Gateway allowed and the Provider
	// failed.
	ResultFailed Result = "failed"
)

// Category is the Gateway error category of a failed request, such as
// "unauthenticated".
type Category string

// Event is one audit event.
type Event struct {
	Time  time.Time `json:"time"`
	Event Name      `json:"event"`
	// RequestID identifies the Gateway request the event belongs to.
	RequestID string `json:"request_id"`
	// ServiceAccount is the sub of the token the event concerns.
	ServiceAccount string `json:"service_account,omitempty"`
	// TokenID is the jti of the token the event concerns, such as the new
	// Root Token of an onboard event.
	TokenID string `json:"jti,omitempty"`
	// ParentTokenID is the jti of the Parent Token presented to issue a
	// Derived Token.
	ParentTokenID string `json:"parent_jti,omitempty"`
	Provider      string `json:"provider,omitempty"`
	// OldKeyID and NewKeyID are the encryption kids a token event moves
	// a token from and to, such as for Resealing. A kid is not a secret.
	OldKeyID string `json:"old_kid,omitempty"`
	NewKeyID string `json:"new_kid,omitempty"`

	// Zone, RecordName and RecordType are what a zone or record request
	// is about, once the Gateway has checked their form. RecordName is
	// relative to Zone.
	Zone       string `json:"zone,omitempty"`
	RecordName string `json:"record_name,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	// Verb is the Permission verb a request needs, such as "list".
	Verb string `json:"verb,omitempty"`
	// RequestedEgress is the Egress the request asked for; empty when it
	// left the choice to the Gateway. Egress is the one it went through.
	RequestedEgress string `json:"requested_egress,omitempty"`
	Egress          string `json:"egress,omitempty"`

	Result Result `json:"result"`
	// Category is the Gateway error category of a failed request.
	Category Category `json:"category,omitempty"`
	// ProviderStatus is the HTTP status of the Provider's error answer.
	ProviderStatus int `json:"provider_status,omitempty"`
	// DurationMS is how long the request took until the event, in
	// milliseconds: for a request the Gateway carried out, including its
	// Provider calls.
	DurationMS int64 `json:"duration_ms"`
}

// Log writes Events to an io.Writer, one JSON object per line.
type Log struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a Log writing to w.
func New(w io.Writer) *Log {
	return &Log{w: w}
}

// Write writes e as one JSON line.
func (l *Log) Write(e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encoding audit event: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}

	return nil
}
