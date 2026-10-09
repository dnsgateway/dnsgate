package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"
)

// The Provider transports of both Egresses bound the TLS handshake and the
// wait for response headers of each Provider request alike.
const (
	providerTLSHandshakeTimeout   = 10 * time.Second
	providerResponseHeaderTimeout = 30 * time.Second
	// gatewayEgressDialTimeout bounds each connection Gateway Egress opens
	// to a Provider.
	gatewayEgressDialTimeout = 10 * time.Second
)

// dialFunc opens a connection to addr, as net.Dialer.DialContext.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// providerTLS is the TLS configuration of every connection to a Provider,
// through either Egress: it verifies the Provider's certificate against
// roots, nil for the system's, and for the Provider's hostname. Nothing
// turns that verification off.
func providerTLS(roots *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
}

// gatewayEgressTransport returns the Provider HTTP transport of Gateway
// Egress: it opens its connections with dial, nil for the network's, and
// verifies the Provider's certificate as providerTLS does. Like the
// default transport, it goes through the proxy the environment names, if
// any, which carries TLS end to end.
func gatewayEgressTransport(dial dialFunc, roots *x509.CertPool) *http.Transport {
	if dial == nil {
		dial = (&net.Dialer{Timeout: gatewayEgressDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	}

	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial,
		TLSClientConfig:       providerTLS(roots),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   providerTLSHandshakeTimeout,
		ResponseHeaderTimeout: providerResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
}
