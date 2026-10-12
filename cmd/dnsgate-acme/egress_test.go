package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"

	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
	"github.com/dnsgateway/dnsgate/internal/server"
	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// providerHost is the API host of the relayed Provider. It resolves
// nowhere but in the Egress Agent's fake resolver, so only Agent Egress
// reaches it.
const providerHost = "api.provider.test"

// agentIP is the public address the Egress Agent's resolver gives
// providerHost: the destination rules of ADR 0002 refuse loopback, so
// the fake network maps this address to the local fake Provider API.
var agentIP = netip.MustParseAddr("203.0.113.7")

// relayNet is the network of the dnsgate-acme daemon acting as Egress
// Agent, and the Provider API at its end: it resolves providerHost to
// agentIP, connects every address to the fake Provider API, and records
// what reached that API.
type relayNet struct {
	api *httptest.Server

	mu      sync.Mutex
	dialed  []string
	reached []string
}

func (n *relayNet) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != providerHost {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}

	return []netip.Addr{agentIP}, nil
}

func (n *relayNet) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, addr)
	n.mu.Unlock()

	return (&net.Dialer{}).DialContext(ctx, network, n.api.Listener.Addr().String())
}

// agent is how the daemon acts as Egress Agent on this network.
func (n *relayNet) agent() *client.EgressAgent {
	return &client.EgressAgent{Resolver: n, Dialer: n}
}

// wantRelayed checks that the Provider API was reached, as providerHost,
// and only through connections the Egress Agent opened to agentIP:443.
func (n *relayNet) wantRelayed(t *testing.T) {
	t.Helper()

	n.mu.Lock()
	dialed, reached := slices.Clone(n.dialed), slices.Clone(n.reached)
	n.mu.Unlock()

	if len(dialed) == 0 || len(reached) == 0 {
		t.Fatalf("the Egress Agent dialed %v and the Provider got %v, want both through the relay", dialed, reached)
	}

	for _, addr := range dialed {
		if want := netip.AddrPortFrom(agentIP, 443).String(); addr != want {
			t.Errorf("the Egress Agent dialed %s, want %s", addr, want)
		}
	}

	for _, host := range reached {
		if host != providerHost {
			t.Errorf("the Provider got a request for %s, want %s", host, providerHost)
		}
	}
}

// relayedProvider is a fake Provider that, as a real one does, sends a
// request to its API, through the HTTP client the Gateway gives it, before
// it resolves a zone. Through Agent Egress, that request is relayed by the
// Egress Agent.
type relayedProvider struct {
	dnsprovider.Provider

	http *http.Client
}

func (p *relayedProvider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+providerHost+"/zones/"+name, nil)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	resp, err := p.http.Do(req)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return dnsprovider.Zone{}, fmt.Errorf("provider API: %s", resp.Status)
	}

	return p.Provider.GetZone(ctx, name)
}

// newRelayE2E is newE2E with the fake Provider behind an API that only
// the Egress Agent reaches: a Gateway that trusts that API's certificate,
// and the network a daemon acting as Egress Agent uses.
func newRelayE2E(t *testing.T) (*e2e, *relayNet) {
	t.Helper()

	cert, roots := providerCert(t)
	n := &relayNet{}

	n.api = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		n.reached = append(n.reached, r.Host)
		n.mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	n.api.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	n.api.Config.ErrorLog = log.New(io.Discard, "", 0)
	n.api.StartTLS()
	t.Cleanup(n.api.Close)

	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: zoneComID, Name: zoneCom, State: dnsprovider.HostingActive}).
		AddZone(dnsprovider.Zone{ID: zoneNetID, Name: zoneNet, State: dnsprovider.HostingActive})

	factory := fake.Factory()
	build := factory.New
	factory.New = func(fields map[string]string, opts ...dnsprovider.Option) (dnsprovider.Provider, error) {
		p, err := build(fields, opts...)
		if err != nil {
			return nil, err
		}

		return &relayedProvider{Provider: p, http: dnsprovider.NewOptions(opts...).HTTPClient}, nil
	}

	env := servertest.NewEnv(t)
	gw := servertest.Launch(t, func(ctx context.Context, audit, logs io.Writer) error {
		return server.Run(ctx, server.Options{
			ConfigFile:      env.Config,
			Listen:          "127.0.0.1:0",
			TLSCertFile:     env.CAFile,
			TLSKeyFile:      env.TLSKeyFile,
			LogLevel:        slog.LevelInfo,
			Audit:           audit,
			Log:             logs,
			Providers:       dnsprovider.Registry{"cloudflare": factory},
			ProviderRootCAs: roots,
		})
	})

	return onboardE2E(t, env, gw, fake), n
}

// providerCert returns a self-signed certificate for providerHost and the
// pool that trusts it.
func providerCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: providerHost},
		DNSNames:              []string{providerHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(parsed)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestEgressAgentRelaysTheProviderConnectionForAnAgentOnlyToken(t *testing.T) {
	e, n := newRelayE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Egress: "agent", Agent: n.agent()})

	d.wantUpdated(t, tok, "examplecom", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
	n.wantRelayed(t)
}

// wantEgressRefused checks that an update at subdomain with tok answers
// 401 forbidden and leaves the Challenge Target empty.
func (e *e2e) wantEgressRefused(t *testing.T, d *acmeDaemon, tok acmeToken, subdomain string) {
	t.Helper()

	code, body := d.update(t, tok, updateBody(subdomain, challenge(1)))
	if code != http.StatusUnauthorized || !jsonEqual(body, `{"error":"forbidden"}`) {
		t.Errorf("POST /update = %d %s, want 401 forbidden\nlogs:\n%s", code, body, d.Logs)
	}

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com")
}

func TestEgressGatewayRefusesAnAgentOnlyToken(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Egress: "gateway"})

	e.wantEgressRefused(t, d, tok, "examplecom")
}

func TestEgressAgentRefusesAGatewayOnlyToken(t *testing.T) {
	e, n := newRelayE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "gateway"))
	d := e.acme(t, daemonConfig{Egress: "agent", Agent: n.agent()})

	e.wantEgressRefused(t, d, tok, "examplecom")

	n.mu.Lock()
	defer n.mu.Unlock()

	if len(n.dialed) != 0 {
		t.Errorf("the Egress Agent dialed %v, want nothing", n.dialed)
	}
}

func TestEgressUnsetLetsTheGatewayChooseAgentEgressForAnAgentOnlyToken(t *testing.T) {
	t.Setenv(gatewayconn.EnvEgress, "")
	_ = os.Unsetenv(gatewayconn.EnvEgress)

	e, n := newRelayE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{Agent: n.agent()})

	d.wantUpdated(t, tok, "examplecom", challenge(1))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.example.com", `60 "`+challenge(1)+`"`)
	n.wantRelayed(t)
}

func TestEgressFallsBackToEnv(t *testing.T) {
	t.Setenv(gatewayconn.EnvEgress, "gateway")

	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}, "agent"))
	d := e.acme(t, daemonConfig{})

	e.wantEgressRefused(t, d, tok, "examplecom")
}

func TestDaemonRefusesToStartWithAnUnknownEgress(t *testing.T) {
	// dnsgate-cli gives the same message, from gatewayconn.ParseEgress.
	const want = `unknown egress "relay": use gateway or agent`

	t.Run("flag", func(t *testing.T) {
		out, err := runCLI(t, append(mapArgs(t), "--listen", heldAddr(t), "--egress", "relay")...)
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q before it listens\n%s", err, want, out)
		}
	})

	t.Run("env", func(t *testing.T) {
		t.Setenv(gatewayconn.EnvEgress, "relay")

		out, err := runCLI(t, append(mapArgs(t), "--listen", heldAddr(t))...)
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q before it listens\n%s", err, want, out)
		}
	})
}
