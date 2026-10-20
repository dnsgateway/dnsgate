package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dnsgateway/dnsgate/internal/gatewayconn"
	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// The zones the fake Provider holds: example.com for direct challenges
// and example.net for CNAME-delegated ones.
const (
	zoneCom   = "example.com"
	zoneComID = "z-com"
	zoneNet   = "example.net"
	zoneNetID = "z-net"
)

// testMap is the Challenge Map most tests serve: a direct Challenge
// Target in example.com and a CNAME-delegated one in example.net.
const testMap = `
examplecom:
  zone: example.com
  name: _acme-challenge
wwwexamplecom:
  zone: example.com
  name: _acme-challenge.www
delegated:
  zone: example.net
  name: challenge-123.acme
`

// e2e is an end-to-end setup for the ACME Endpoint: a Gateway served in
// the test process over TLS, with a fake Provider behind it as
// "cloudflare", and a Root Token for it. ACME tokens are derived from the
// Root Token through the Gateway client; dnsgate-acme daemons are started
// against the Gateway with acme.
type e2e struct {
	// Env is the Gateway's configuration; Env.CAFile verifies it.
	Env *servertest.Env
	// Gateway is the running Gateway: its address, audit and logs.
	Gateway *servertest.Gateway
	// Fake is the Provider behind the Gateway.
	Fake *providertest.Provider
	// Client calls the Gateway directly, to set tokens up.
	Client *client.Client
	// Root is the Root Token.
	Root string
}

// newE2E serves a Gateway whose fake Provider holds example.com and
// example.net, and onboards a Root Token for it.
func newE2E(t *testing.T) *e2e {
	t.Helper()

	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: zoneComID, Name: zoneCom, State: dnsprovider.HostingActive}).
		AddZone(dnsprovider.Zone{ID: zoneNetID, Name: zoneNet, State: dnsprovider.HostingActive})

	return newE2EWith(t, fake, dnsprovider.Registry{"cloudflare": fake.Factory()})
}

// newE2EWith serves a Gateway calling providers, whose "cloudflare" is
// fake (nil when it is not a providertest one), and onboards a Root Token
// for it.
func newE2EWith(t *testing.T, fake *providertest.Provider, providers dnsprovider.Registry) *e2e {
	t.Helper()

	env := servertest.NewEnv(t)

	return onboardE2E(t, env, servertest.Start(t, env.Config, providers), fake)
}

// onboardE2E onboards a Root Token for the Gateway gw, configured by env,
// whose "cloudflare" is fake (nil when it is not a providertest one).
func onboardE2E(t *testing.T, env *servertest.Env, gw *servertest.Gateway, fake *providertest.Provider) *e2e {
	t.Helper()

	c, closeConn, err := gatewayconn.Dial(gw.Addr, []string{env.CAFile})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(closeConn)

	resp, err := c.Onboard(t.Context(), &dnsgatev1.OnboardRequest{
		BootstrapSecret: servertest.BootstrapSecret,
		Provider:        "cloudflare",
		Credential:      &dnsgatev1.Credential{Type: "api-token", Value: "cf-api-token"},
	})
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	return &e2e{Env: env, Gateway: gw, Fake: fake, Client: c, Root: resp.GetToken()}
}

// acmeToken is a Service Token for an ACME client: what it sends as
// X-Api-Key, and its ID, what it sends as X-Api-User.
type acmeToken struct {
	Key  string
	User string
}

// token derives a Derived Token of the Root Token with perms, expiring in
// an hour, as an Administrator issues ACME tokens.
func (e *e2e) token(t *testing.T, perms ...*dnsgatev1.Permission) acmeToken {
	t.Helper()

	return e.tokenExpiring(t, time.Hour, perms...)
}

// tokenExpiring derives a Derived Token of the Root Token with perms,
// expiring in expires.
func (e *e2e) tokenExpiring(t *testing.T, expires time.Duration, perms ...*dnsgatev1.Permission) acmeToken {
	t.Helper()

	resp, err := e.Client.CreateToken(t.Context(), &dnsgatev1.CreateTokenRequest{
		Token:       e.Root,
		Sub:         "acme-client",
		Permissions: perms,
		Expires:     durationpb.New(expires),
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	return acmeToken{Key: resp.GetToken(), User: resp.GetJti()}
}

// patchTXT is a Permission to patch TXT records at names in zone through
// egress (any egress when empty), as an ACME token holds.
func patchTXT(zone string, names []string, egress ...string) *dnsgatev1.Permission {
	return &dnsgatev1.Permission{
		Verbs: []string{"patch"}, Resources: []string{"records"},
		Zones: []string{zone}, Names: names, Types: []string{"TXT"}, Egress: egress,
	}
}

// writeMap writes a Challenge Map file named name holding content and
// returns its path. The extension of name tells YAML from JSON only to
// the reader: the daemon accepts either.
func writeMap(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	servertest.WriteFile(t, path, content, 0o600)

	return path
}

// acmeDaemon is a dnsgate-acme daemon running in the test process.
type acmeDaemon struct {
	// Base is its URL, such as http://127.0.0.1:1234.
	Base string
	// HTTP is the client that reaches it, over HTTPS when it serves it.
	HTTP *http.Client
	// Logs are what it logged, as JSON lines.
	Logs *servertest.SyncBuffer
}

// daemonConfig configures a dnsgate-acme daemon started by acme.
type daemonConfig struct {
	// Map is the Challenge Map file's content, YAML or JSON; empty means
	// testMap.
	Map string
	// MapFile names the Challenge Map file; empty means "map.yaml".
	MapFile string
	// Egress is its --egress; empty leaves it out, so the Gateway chooses.
	Egress string
	// TLS serves HTTPS with a certificate for 127.0.0.1.
	TLS bool
	// Args are further flags, after the ones above, so they override them.
	Args []string
	// Agent is how it acts as Egress Agent; nil means the network's.
	Agent *client.EgressAgent
}

// acme starts a dnsgate-acme daemon on an ephemeral port, pointed at the
// Gateway and trusting its CA, until the test ends.
func (e *e2e) acme(t *testing.T, cfg daemonConfig) *acmeDaemon {
	t.Helper()

	if cfg.Map == "" {
		cfg.Map = testMap
	}

	if cfg.MapFile == "" {
		cfg.MapFile = "map.yaml"
	}

	args := []string{
		"--gateway", e.Gateway.Addr,
		"--ca-file", e.Env.CAFile,
		"--challenge-map", writeMap(t, cfg.MapFile, cfg.Map),
	}

	if cfg.Egress != "" {
		args = append(args, "--egress", cfg.Egress)
	}

	d := &acmeDaemon{HTTP: &http.Client{}}
	scheme := "http"

	if cfg.TLS {
		cert, key := writeTLSFiles(t)
		args = append(args, "--tls-cert-file", cert, "--tls-key-file", key)
		d.HTTP = httpsClient(t, cert, tls.VersionTLS13)
		scheme = "https"
	}

	var opts []client.Option
	if cfg.Agent != nil {
		opts = append(opts, client.WithEgressAgent(*cfg.Agent))
	}

	gw := startDaemonWith(t, opts, append(args, cfg.Args...)...)
	d.Base, d.Logs = scheme+"://"+gw.Addr, gw.Logs

	return d
}

// update sends POST /update with tok's credentials and body as is, and
// returns the status and body of the response.
func (d *acmeDaemon) update(t *testing.T, tok acmeToken, body string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, d.Base+"/update", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-User", tok.User)
	req.Header.Set("X-Api-Key", tok.Key)

	resp, err := d.HTTP.Do(req)
	if err != nil {
		t.Fatalf("POST /update: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, string(got)
}

// updateBody is the acme-dns /update request body for subdomain and txt.
func updateBody(subdomain, txt string) string {
	b, _ := json.Marshal(map[string]string{"subdomain": subdomain, "txt": txt})

	return string(b)
}

// wantUpdated sends an update of txt at subdomain with tok and checks that
// it answers exactly 200 {"txt": txt}.
func (d *acmeDaemon) wantUpdated(t *testing.T, tok acmeToken, subdomain, txt string) {
	t.Helper()

	code, body := d.update(t, tok, updateBody(subdomain, txt))
	if want := `{"txt":"` + txt + `"}`; code != http.StatusOK || !jsonEqual(body, want) {
		t.Fatalf("POST /update = %d %s, want 200 %s\nlogs:\n%s", code, body, want, d.Logs)
	}
}

// jsonEqual reports whether got is a JSON object equal to want.
func jsonEqual(got, want string) bool {
	var g, w map[string]any
	if json.Unmarshal([]byte(got), &g) != nil || json.Unmarshal([]byte(want), &w) != nil {
		return false
	}

	return fmt.Sprint(g) == fmt.Sprint(w)
}

// txtAt returns the TXT records the fake Provider holds at the absolute
// name in the zone with zoneID, each as "TTL value", sorted. Reading them
// is itself a Provider call, so check Fake.Calls before it.
func (e *e2e) txtAt(t *testing.T, zoneID, zone, name string) []string {
	t.Helper()

	set, err := e.Fake.ListRecords(t.Context(), dnsprovider.Zone{ID: zoneID, Name: zone}, dnsprovider.RecordFilter{Type: "TXT"})
	if err != nil {
		t.Fatal(err)
	}

	var out []string

	for _, r := range set.Records {
		if r.Name == name {
			out = append(out, fmt.Sprintf("%d %s", r.TTL, r.Value))
		}
	}

	slices.Sort(out)

	return out
}

// wantTXT checks that the fake Provider holds exactly want, as txtAt
// formats them, at the absolute name in the zone with zoneID.
func (e *e2e) wantTXT(t *testing.T, zoneID, zone, name string, want ...string) {
	t.Helper()

	slices.Sort(want)

	if got := e.txtAt(t, zoneID, zone, name); !slices.Equal(got, want) {
		t.Errorf("TXT at %s = %q, want %q", name, got, want)
	}
}

// challenge returns a valid acme-dns challenge value, 43 characters of
// base64url, distinct for each seed.
func challenge(seed byte) string {
	return strings.Repeat(string('A'+seed%26), 40) + "_-0"
}

// acmeproxy sends POST path, /present or /cleanup, with body as is and
// tok's credentials as HTTP Basic auth, its ID as the username and the
// Service Token as the password, or no Authorization header when tok is
// empty. It returns the status and body of the response.
func (d *acmeDaemon) acmeproxy(t *testing.T, path string, tok acmeToken, body string) (int, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, d.Base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	if tok != (acmeToken{}) {
		req.SetBasicAuth(tok.User, tok.Key)
	}

	resp, err := d.HTTP.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}

	defer func() { _ = resp.Body.Close() }()

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, string(got)
}

// present sends POST /present with tok's credentials and body as is, and
// returns the status and body of the response.
func (d *acmeDaemon) present(t *testing.T, tok acmeToken, body string) (int, string) {
	t.Helper()

	return d.acmeproxy(t, "/present", tok, body)
}

// acmeproxyBody is the acmeproxy request body for fqdn and value.
func acmeproxyBody(fqdn, value string) string {
	b, _ := json.Marshal(map[string]string{"fqdn": fqdn, "value": value})

	return string(b)
}

// wantPresented sends a /present of value at fqdn with tok and checks
// that it answers exactly 200 with the request echoed.
func (d *acmeDaemon) wantPresented(t *testing.T, tok acmeToken, fqdn, value string) {
	t.Helper()

	body := acmeproxyBody(fqdn, value)

	code, got := d.present(t, tok, body)
	if code != http.StatusOK || !jsonEqual(got, body) {
		t.Fatalf("POST /present = %d %s, want 200 %s\nlogs:\n%s", code, got, body, d.Logs)
	}
}
