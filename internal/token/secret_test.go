package token_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsgate/internal/token"
)

func TestClaimsAndCredentialNeverPrintTheProviderCredential(t *testing.T) {
	claims := derivedClaims()
	cred := claims.Credential

	var out []string

	for _, v := range []any{claims, &claims, cred, &cred, cred.Value, &cred.Value} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			out = append(out, fmt.Sprintf(verb, v))
		}

		out = append(out, fmt.Sprint(v), fmt.Sprintln(v))

		js, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}

		out = append(out, string(js))

		out = append(out, fmt.Errorf("opening %v: %w", v, errors.New("boom")).Error())
	}

	text, err := cred.Value.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	out = append(out, string(text))

	var logs bytes.Buffer

	for _, h := range []slog.Handler{slog.NewJSONHandler(&logs, nil), slog.NewTextHandler(&logs, nil)} {
		slog.New(h).Info("token", "claims", claims, "credential", cred, "secret", cred.Value, "ptr", &claims)
	}

	out = append(out, logs.String())

	for _, s := range out {
		if strings.Contains(s, testCredential) || strings.Contains(s, fmt.Sprintf("%x", testCredential)) {
			t.Errorf("Provider Credential printed: %s", s)
		}
	}

	if !strings.Contains(fmt.Sprintf("%+v", cred), "api-token") {
		t.Errorf("credential type should stay visible: %+v", cred)
	}

	if cred.Value.Reveal() != testCredential {
		t.Error("Reveal does not return the credential")
	}
}

func TestSecretIsRedactedInJSON(t *testing.T) {
	js, err := json.Marshal(token.Credential{Type: "api-token", Value: token.NewSecret(testCredential)})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := string(js), `{"type":"api-token","value":"[REDACTED]"}`; got != want {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}
