package token

import (
	"encoding/base64"
	"testing"
)

// TestConcatKDFMatchesRFC7518AppendixC checks the Concat KDF against the
// worked ECDH-ES example of RFC 7518 Appendix C.
func TestConcatKDFMatchesRFC7518AppendixC(t *testing.T) {
	z := []byte{
		158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
		38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
		140, 254, 144, 196,
	}

	key, err := concatKDF(z, "A128GCM", []byte("Alice"), []byte("Bob"), 16)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := base64.RawURLEncoding.EncodeToString(key), "VqqN6vgjbSBcIijNcacQGg"; got != want {
		t.Errorf("derived key = %s, want %s", got, want)
	}
}
