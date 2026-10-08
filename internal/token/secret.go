package token

import (
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret holds a value, such as a Provider Credential, that must never be
// printed. Every formatting path (fmt verbs, String, GoString, JSON, text
// marshaling and slog) yields "[REDACTED]"; only Reveal returns the value.
// The token codec seals the real value through its own wire format.
type Secret struct {
	value string
}

// NewSecret wraps value.
func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal returns the plaintext value. Call it only where the value is used,
// such as when building the Provider client.
func (s Secret) Reveal() string { return s.value }

// IsZero reports whether the Secret is empty.
func (s Secret) IsZero() bool { return s.value == "" }

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer.
func (Secret) GoString() string { return redacted }

// Format implements fmt.Formatter so that no verb reveals the value.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalText implements encoding.TextMarshaler.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }
