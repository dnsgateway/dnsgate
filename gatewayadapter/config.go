package gatewayadapter

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/dnsgateway/dnsprovider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
	"github.com/dnsgateway/dnsgate/internal/permission"
	"github.com/dnsgateway/dnsgate/internal/provider"
)

// The fields the Factory builds a Gateway Adapter from.
const (
	// FieldGateway is the Gateway's address, host:port.
	FieldGateway = "gateway"
	// FieldToken is the Service Token every call presents.
	FieldToken = "token"
	// FieldEgress is the Egress every call asks for: "auto", "gateway" or
	// "agent".
	FieldEgress = "egress"
)

// The values FieldEgress takes.
const (
	// egressAuto leaves the Egress to the Gateway: Gateway Egress where
	// the token allows it, else Agent Egress.
	egressAuto = "auto"
	// egressGateway asks for Gateway Egress.
	egressGateway = string(permission.EgressGateway)
	// egressAgent asks for Agent Egress: the Gateway Adapter is the
	// Egress Agent.
	egressAgent = string(permission.EgressAgent)
)

// apiEgress returns the API's Egress the FieldEgress value v asks for,
// one of its Choices.
func apiEgress(v string) dnsgatev1.Egress {
	if v == egressAuto {
		v = ""
	}

	e, _ := permission.Egress(v).API()

	return e
}

// fields are the Factory's fields, in form order.
var fields = []dnsprovider.Field{
	{Name: FieldGateway, Label: "Gateway address"},
	{Name: FieldToken, Label: "Service Token", Secret: true},
	{Name: FieldEgress, Label: "Egress", Default: egressAuto, Choices: []string{egressAuto, egressGateway, egressAgent}},
}

// Config is what a Gateway Adapter is built from.
type Config struct {
	// Gateway is the Gateway's address, host:port.
	Gateway string
	// Token is the Service Token every call presents.
	Token string
	// Egress is the Egress every call asks for; EGRESS_UNSPECIFIED
	// leaves it to the Gateway.
	Egress dnsgatev1.Egress
	// RootCAs are the CA certificates the Gateway's certificate is
	// verified against; nil means the system's.
	RootCAs *x509.CertPool

	// providers are the Provider types the token's Provider is looked up
	// in; nil means those the Gateway supports.
	providers dnsprovider.Registry
}

// Option configures the Factory.
type Option func(*options)

type options struct {
	rootCAs   *x509.CertPool
	providers dnsprovider.Registry
}

// WithRootCAs makes every Gateway Adapter the Factory builds verify the
// Gateway's certificate against pool, in place of the system's CA
// certificates. Trust in the Gateway is set once for the process, not
// per Account.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(o *options) { o.rootCAs = pool }
}

// Factory builds Gateway Adapters from the fields FieldGateway,
// FieldToken and FieldEgress, the last optional. It declares no Zone
// writes: the Gateway has none. Its TTL and Record Extras are left
// unset: they are those of each token's Provider type, which each
// Gateway Adapter reports itself.
func Factory(opts ...Option) dnsprovider.Factory {
	var o options

	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	return dnsprovider.Factory{
		Fields: slices.Clone(fields),
		New: func(m map[string]string, popts ...dnsprovider.Option) (dnsprovider.Provider, error) {
			m, err := checkFields(m)
			if err != nil {
				return nil, err
			}

			return New(Config{
				Gateway:   m[FieldGateway],
				Token:     m[FieldToken],
				Egress:    apiEgress(m[FieldEgress]),
				RootCAs:   o.rootCAs,
				providers: o.providers,
			}, popts...)
		},
	}
}

// checkFields refuses a field map holding a field the Factory does not
// take or an Egress it does not know, and returns it with the Egress
// filled in when left out. Its errors never quote a value: one may be the
// Service Token.
func checkFields(m map[string]string) (map[string]string, error) {
	var unknown []string

	for name := range m {
		if !slices.ContainsFunc(fields, func(f dnsprovider.Field) bool { return f.Name == name }) {
			unknown = append(unknown, name)
		}
	}

	if len(unknown) > 0 {
		slices.Sort(unknown)

		return nil, fmt.Errorf("gateway adapter: unknown field %s", strings.Join(unknown, ", "))
	}

	out := maps.Clone(m)
	if out == nil {
		out = map[string]string{}
	}

	for _, f := range fields {
		v := out[f.Name]
		if v == "" {
			out[f.Name] = f.Default

			continue
		}

		if len(f.Choices) > 0 && !slices.Contains(f.Choices, v) {
			return nil, fmt.Errorf("gateway adapter: field %s must be one of %s", f.Name, strings.Join(f.Choices, ", "))
		}
	}

	return out, nil
}

// New builds a Gateway Adapter from cfg without a network call. Of opts,
// it reads only dnsprovider.WithBaseURL, which takes the place of
// cfg.Gateway, for tests: the Gateway is no HTTP API.
func New(cfg Config, opts ...dnsprovider.Option) (dnsprovider.Provider, error) {
	if u := dnsprovider.NewOptions(opts...).BaseURL; u != "" {
		cfg.Gateway = u
	}

	switch {
	case cfg.Gateway == "":
		return nil, errors.New("gateway adapter: no Gateway address")
	case cfg.Token == "":
		return nil, errors.New("gateway adapter: no Service Token")
	}

	if _, ok := permission.EgressFromAPI(cfg.Egress); !ok {
		return nil, errors.New("gateway adapter: unknown Egress")
	}

	conn, err := dial(cfg.Gateway, cfg.RootCAs)
	if err != nil {
		return nil, err
	}

	providers := cfg.providers
	if providers == nil {
		providers = provider.Registry()
	}

	return &adapter{
		client:    client.New(conn),
		token:     cfg.Token,
		egress:    cfg.Egress,
		providers: providers,
	}, nil
}

// gatewayConn is a connection to the Gateway, and the CA certificates its
// certificate is verified against: a copy of those it was opened with,
// nil for the system's.
type gatewayConn struct {
	roots *x509.CertPool
	conn  *grpc.ClientConn
}

// conns are the connections to the Gateway by address, one per address
// and set of CA certificates, kept for the life of the process: a
// dnsprovider.Provider is never closed, and every Gateway Adapter of an
// address shares one.
var conns = struct {
	sync.Mutex

	m map[string][]gatewayConn
}{m: map[string][]gatewayConn{}}

// dial returns the connection to the Gateway at addr, verified against
// roots, opening it on first use. A pool that holds the same CA
// certificates as one dialed before shares its connection, and a change
// to roots after dial changes no connection. grpc.NewClient connects
// lazily, on the first call.
func dial(addr string, roots *x509.CertPool) (*grpc.ClientConn, error) {
	conns.Lock()
	defer conns.Unlock()

	for _, c := range conns.m[addr] {
		if c.roots.Equal(roots) {
			return c.conn, nil
		}
	}

	if roots != nil {
		roots = roots.Clone()
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})))
	if err != nil {
		return nil, fmt.Errorf("gateway adapter: connecting to the Gateway: %w", err)
	}

	conns.m[addr] = append(conns.m[addr], gatewayConn{roots: roots, conn: conn})

	return conn, nil
}
