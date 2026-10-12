package gatewayconn_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsprovider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

func TestParseEgress(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]dnsgatev1.Egress{
		"":        dnsgatev1.Egress_EGRESS_UNSPECIFIED,
		"gateway": dnsgatev1.Egress_EGRESS_GATEWAY,
		"agent":   dnsgatev1.Egress_EGRESS_AGENT,
	} {
		got, err := gatewayconn.ParseEgress(value)
		if err != nil || got != want {
			t.Errorf("ParseEgress(%q) = %v, %v; want %v", value, got, err, want)
		}
	}
}

func TestParseEgressUnknown(t *testing.T) {
	t.Parallel()

	_, err := gatewayconn.ParseEgress("relay")
	if err == nil || err.Error() != `unknown egress "relay": use gateway or agent` {
		t.Fatalf("ParseEgress(relay) error = %v", err)
	}
}

func TestDialRefuses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")

	if err := os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		gateway string
		caFiles []string
		want    string
	}{
		"unreadable CA file":              {"localhost:8443", []string{filepath.Join(dir, "missing.pem")}, "reading CA file: "},
		"CA file with no PEM certificate": {"localhost:8443", []string{notPEM}, "CA file " + notPEM + " holds no PEM certificate"},
		"no address":                      {"", nil, "no Gateway address: set --gateway or DNSGATE_GATEWAY"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, closeConn, err := gatewayconn.Dial(tc.gateway, tc.caFiles)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Dial error = %v; want prefix %q", err, tc.want)
			}

			if c != nil || closeConn != nil {
				t.Fatal("Dial returned a client with its error")
			}
		})
	}
}

// TestDialTrustsCAFile reaches a Gateway whose certificate only the CA
// file verifies: the Gateway answers a garbage token as unauthenticated,
// which it can only do once the TLS handshake succeeded.
func TestDialTrustsCAFile(t *testing.T) {
	t.Parallel()

	env := servertest.NewEnv(t)
	gw := servertest.Start(t, env.Config, dnsprovider.Registry{})

	c, closeConn, err := gatewayconn.Dial(gw.Addr, []string{env.CAFile})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	defer closeConn()

	_, err = c.InspectToken(t.Context(), "garbage")
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("InspectToken error = %v; want Unauthenticated", err)
	}
}
