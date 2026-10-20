// Package gatewayconn connects a Gateway client, such as dnsgate-cli or
// the ACME Endpoint, to the Gateway: it dials the Gateway over TLS and
// turns the --egress flag into the API's Egress.
package gatewayconn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/dnsgateway/dnsgate/internal/permission"
)

// Names of the flags and environment variables every Gateway client
// shares.
const (
	FlagGateway = "gateway"
	FlagCAFile  = "ca-file"
	FlagEgress  = "egress"

	EnvGateway = "DNSGATE_GATEWAY"
	EnvCAFile  = "DNSGATE_CA_FILE"
	EnvEgress  = "DNSGATE_EGRESS"

	// DefaultGateway is the Gateway address used when neither the flag
	// nor the environment gives one.
	DefaultGateway = "localhost:8443"
)

// ParseEgress returns the API's Egress that value, an --egress flag,
// names: gateway, agent, or empty to let the Gateway choose.
func ParseEgress(value string) (dnsgatev1.Egress, error) {
	egress, ok := permission.Egress(value).API()
	if !ok {
		return 0, errors.New(`unknown egress "` + value + `": use gateway or agent`)
	}

	return egress, nil
}

// EgressValue is an --egress flag: a pflag.Value that takes what
// ParseEgress does and sets the Egress it points at.
type EgressValue struct {
	egress *dnsgatev1.Egress
	name   string
}

// NewEgressValue returns the EgressValue that sets egress, with no
// default: the Gateway chooses.
func NewEgressValue(egress *dnsgatev1.Egress) *EgressValue {
	return &EgressValue{egress: egress}
}

// Set sets the Egress that value names, as ParseEgress parses it.
func (v *EgressValue) Set(value string) error {
	egress, err := ParseEgress(value)
	if err != nil {
		return err
	}

	*v.egress, v.name = egress, value

	return nil
}

// String returns the name of the Egress set.
func (v *EgressValue) String() string {
	return v.name
}

// Type is "string", so the help shows an --egress as one.
func (v *EgressValue) Type() string {
	return "string"
}

// Dial connects to the Gateway at gateway, a host:port, over TLS,
// verifying it against the certificates of every file in caFiles or,
// without one, the system's CA certificates. The client takes opts.
// closeConn releases the connection.
func Dial(gateway string, caFiles []string, opts ...client.Option) (c *client.Client, closeConn func(), err error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if len(caFiles) > 0 {
		pool := x509.NewCertPool()

		for _, file := range caFiles {
			pem, err := os.ReadFile(file)
			if err != nil {
				return nil, nil, fmt.Errorf("reading CA file: %w", err)
			}

			if !pool.AppendCertsFromPEM(pem) {
				return nil, nil, fmt.Errorf("CA file %s holds no PEM certificate", file)
			}
		}

		tlsCfg.RootCAs = pool
	}

	if gateway == "" {
		return nil, nil, errors.New("no Gateway address: set --" + FlagGateway + " or " + EnvGateway)
	}

	conn, err := grpc.NewClient(gateway, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to the Gateway: %w", err)
	}

	return client.New(conn, opts...), func() { _ = conn.Close() }, nil
}
