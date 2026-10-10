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
	egressGateway = "gateway"
	// egressAgent asks for Agent Egress: the Gateway Adapter is the
	// Egress Agent.
	egressAgent = "agent"
)

// egresses maps each FieldEgress value to the API's Egress.
var egresses = map[string]dnsgatev1.Egress{
	egressAuto:    dnsgatev1.Egress_EGRESS_UNSPECIFIED,
	egressGateway: dnsgatev1.Egress_EGRESS_GATEWAY,
	egressAgent:   dnsgatev1.Egress_EGRESS_AGENT,
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
				Egress:    egresses[m[FieldEgress]],
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
	case !slices.Contains(slices.Collect(maps.Values(egresses)), cfg.Egress):
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

// connKey names a connection to the Gateway: its address, and the CA
// certificates its certificate is verified against.
type connKey struct {
	addr  string
	roots *x509.CertPool
}

// conns are the connections to the Gateway, one per address and trust,
// kept for the life of the process: a dnsprovider.Provider is never
// closed, and every Gateway Adapter of an address shares one.
var conns = struct {
	sync.Mutex

	m map[connKey]*grpc.ClientConn
}{m: map[connKey]*grpc.ClientConn{}}

// dial returns the connection to the Gateway at addr, verified against
// roots, opening it on first use. grpc.NewClient connects lazily, on the
// first call.
func dial(addr string, roots *x509.CertPool) (*grpc.ClientConn, error) {
	conns.Lock()
	defer conns.Unlock()

	key := connKey{addr: addr, roots: roots}
	if conn, ok := conns.m[key]; ok {
		return conn, nil
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})))
	if err != nil {
		return nil, fmt.Errorf("gateway adapter: connecting to the Gateway: %w", err)
	}

	conns.m[key] = conn

	return conn, nil
}
