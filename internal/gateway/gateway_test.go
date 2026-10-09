package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/audit"
	"github.com/dnsgateway/dnsgate/internal/client"
	"github.com/dnsgateway/dnsgate/internal/gateway"
	"github.com/dnsgateway/dnsgate/internal/keys"
	"github.com/dnsgateway/dnsgate/internal/token"
)

const (
	bootstrapSecret = "bootstrap-secret-0123456789"
	cfToken         = "cf-api-token-SECRET-value"
)

// harness is a Gateway served in-process over an in-memory listener.
type harness struct {
	client *client.Client
	api    dnsgatev1.GatewayServiceClient
	audit  *syncBuffer
	// logs holds the Gateway's operational logs.
	logs *syncBuffer
	now  time.Time
	// fake is the Provider the Gateway calls, as "cloudflare".
	fake *providertest.Provider
	// keys are the keys of the Gateway last served.
	keys keys.Source

	auditTo io.Writer
	keyDir  string
}

// syncBuffer is a bytes.Buffer safe for the Gateway's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	buf := &syncBuffer{}
	h := newHarnessAuditingTo(t, buf)
	h.audit = buf

	return h
}

// newHarnessAuditingTo returns a harness whose Gateway writes its audit
// events to w. Its keys have the kid suffix "test".
func newHarnessAuditingTo(t *testing.T, w io.Writer) *harness {
	t.Helper()

	h := &harness{
		now:     time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		auditTo: w,
		logs:    &syncBuffer{},
		keyDir:  filepath.Join(t.TempDir(), "keys"),
		fake:    providertest.New(),
	}

	if _, err := keys.Generate(h.keyDir, "test"); err != nil {
		t.Fatal(err)
	}

	h.serve(t, h.loadKeys(t, "enc-test"))

	return h
}

// loadKeys loads the signing key sig-test with encKID as the current
// encryption key.
func (h *harness) loadKeys(t *testing.T, encKID string, opts ...keys.Option) *keys.Files {
	t.Helper()

	src, err := keys.LoadFiles(filepath.Join(h.keyDir, "sig-test.pem"), filepath.Join(h.keyDir, encKID+".pem"), opts...)
	if err != nil {
		t.Fatal(err)
	}

	return src
}

// rotate restarts the Gateway with a new encryption key, enc-next, as the
// current key, keeping enc-test as a decryption key until retireAt. It
// returns the new key's kid.
func (h *harness) rotate(t *testing.T, retireAt time.Time) string {
	t.Helper()

	if _, err := keys.Generate(h.keyDir, "next"); err != nil {
		t.Fatal(err)
	}

	h.serve(t, h.loadKeys(t, "enc-next", keys.WithDecryptionKey(filepath.Join(h.keyDir, "enc-test.pem"), retireAt)))

	return "enc-next"
}

// serve starts a Gateway using src and points the harness clients at it.
func (h *harness) serve(t *testing.T, src keys.Source) {
	t.Helper()

	gw := gateway.New(gateway.Config{
		Keys:            src,
		BootstrapSecret: token.NewSecret(bootstrapSecret),
		Audit:           audit.New(h.auditTo),
		Providers:       dnsprovider.Registry{"cloudflare": h.fake.Factory()},
		Logger:          slog.New(slog.NewTextHandler(h.logs, nil)),
		Now:             func() time.Time { return h.now },
	})

	h.keys = src

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	dnsgatev1.RegisterGatewayServiceServer(srv, gw)

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	h.client = client.New(conn)
	h.api = dnsgatev1.NewGatewayServiceClient(conn)
}

func onboardRequest() *dnsgatev1.OnboardRequest {
	return &dnsgatev1.OnboardRequest{
		BootstrapSecret: bootstrapSecret,
		Provider:        "cloudflare",
		Credential:      &dnsgatev1.Credential{Type: "api-token", Value: cfToken},
	}
}

func (h *harness) onboard(t *testing.T, req *dnsgatev1.OnboardRequest) string {
	t.Helper()

	resp, err := h.client.Onboard(t.Context(), req)
	if err != nil {
		t.Fatalf("Onboard: %v", err)
	}

	return resp.GetToken()
}

func TestOnboardReturnsRootTokenWithFullPermissionsAndNoExpiry(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	got, err := h.client.InspectToken(t.Context(), root)
	if err != nil {
		t.Fatalf("InspectToken: %v", err)
	}

	if got.GetSub() != "root" {
		t.Errorf("sub = %q, want root", got.GetSub())
	}

	if !strings.HasPrefix(got.GetJti(), "tok_") {
		t.Errorf("jti = %q, want a tok_ prefix", got.GetJti())
	}

	if got.GetProvider() != "cloudflare" {
		t.Errorf("provider = %q, want cloudflare", got.GetProvider())
	}

	if len(got.GetAncestors()) != 0 {
		t.Errorf("ancestors = %v, want none", got.GetAncestors())
	}

	if got.Exp != nil {
		t.Errorf("exp = %v, want none", got.GetExp().AsTime())
	}

	if iat := got.GetIat().AsTime(); !iat.Equal(h.now) {
		t.Errorf("iat = %v, want %v", iat, h.now)
	}

	want := []*dnsgatev1.Permission{{
		Verbs:     []string{"get", "list", "create", "update", "patch", "delete"},
		Resources: []string{"zones", "records", "tokens"},
		Zones:     []string{"*"},
		Names:     []string{"@", "**"},
		Types:     []string{"*"},
		Egress:    []string{"gateway", "agent"},
	}}

	if !samePermissions(got.GetPermissions(), want) {
		t.Errorf("permissions = %v, want %v", got.GetPermissions(), want)
	}
}

func samePermissions(got, want []*dnsgatev1.Permission) bool {
	return slices.EqualFunc(got, want, func(a, b *dnsgatev1.Permission) bool {
		return slices.Equal(a.GetVerbs(), b.GetVerbs()) &&
			slices.Equal(a.GetResources(), b.GetResources()) &&
			slices.Equal(a.GetZones(), b.GetZones()) &&
			slices.Equal(a.GetNames(), b.GetNames()) &&
			slices.Equal(a.GetTypes(), b.GetTypes()) &&
			slices.Equal(a.GetEgress(), b.GetEgress())
	})
}

// wantError checks that err is a Gateway error with code and category.
func wantError(t *testing.T, err error, code codes.Code, category dnsgatev1.Error_Category) {
	t.Helper()

	st := status.Convert(err)
	if err == nil || st.Code() != code {
		t.Fatalf("error = %v, want code %v", err, code)
	}

	for _, d := range st.Details() {
		if e, ok := d.(*dnsgatev1.Error); ok {
			if e.GetCategory() != category {
				t.Errorf("category = %v, want %v", e.GetCategory(), category)
			}

			return
		}
	}

	t.Errorf("error %v has no Error detail", err)
}

func TestOnboardRejectsWrongOrMissingBootstrapSecret(t *testing.T) {
	for name, secret := range map[string]string{
		"wrong":   "not-the-bootstrap-secret",
		"missing": "",
		"prefix":  bootstrapSecret[:10],
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			req := onboardRequest()
			req.BootstrapSecret = secret

			resp, err := h.client.Onboard(t.Context(), req)
			wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)

			if resp.GetToken() != "" {
				t.Error("a token was returned")
			}
		})
	}
}

func TestOnboardExpiresSetsExp(t *testing.T) {
	h := newHarness(t)

	req := onboardRequest()
	req.Expires = durationpb.New(90 * 24 * time.Hour)

	got, err := h.client.InspectToken(t.Context(), h.onboard(t, req))
	if err != nil {
		t.Fatalf("InspectToken: %v", err)
	}

	want := time.Date(2027, 1, 6, 12, 0, 0, 0, time.UTC)
	if got.Exp == nil || !got.GetExp().AsTime().Equal(want) {
		t.Errorf("exp = %v, want %v", got.GetExp().AsTime(), want)
	}
}

func TestOnboardRejectsNonPositiveExpires(t *testing.T) {
	for name, d := range map[string]time.Duration{"zero": 0, "negative": -time.Hour, "under a second": time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			req := onboardRequest()
			req.Expires = durationpb.New(d)

			_, err := h.client.Onboard(t.Context(), req)
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)
		})
	}
}

// auditEvents decodes the audit log, one JSON object per line.
func (h *harness) auditEvents(t *testing.T) []map[string]any {
	t.Helper()

	var events []map[string]any

	for line := range strings.Lines(h.audit.String()) {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q is not JSON: %v", line, err)
		}

		events = append(events, e)
	}

	return events
}

func TestOnboardWritesAuditEvent(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	got, err := h.client.InspectToken(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}

	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit events = %v, want one", events)
	}

	e := events[0]

	for field, want := range map[string]any{
		"time":            "2026-10-08T12:00:00Z",
		"event":           "onboard",
		"jti":             got.GetJti(),
		"provider":        "cloudflare",
		"service_account": "root",
		"result":          "ok",
	} {
		if e[field] != want {
			t.Errorf("audit %s = %v, want %v", field, e[field], want)
		}
	}

	if id, _ := e["request_id"].(string); !strings.HasPrefix(id, "req_") {
		t.Errorf("audit request_id = %v, want a req_ prefix", e["request_id"])
	}
}

func TestOnboardAuditsDenials(t *testing.T) {
	h := newHarness(t)

	req := onboardRequest()
	req.BootstrapSecret = "wrong"

	if _, err := h.client.Onboard(t.Context(), req); err == nil {
		t.Fatal("onboard with a wrong bootstrap secret succeeded")
	}

	events := h.auditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit events = %v, want one", events)
	}

	if e := events[0]; e["event"] != "onboard" || e["result"] != "denied" || e["category"] != "unauthenticated" {
		t.Errorf("audit event = %v, want a denied onboard, category unauthenticated", e)
	}
}

// failingWriter fails every write, like an audit log on a full disk.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestOnboardReturnsNoRootTokenWhenItsAuditEventIsLost(t *testing.T) {
	h := newHarnessAuditingTo(t, failingWriter{})

	resp, err := h.client.Onboard(t.Context(), onboardRequest())
	wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

	if resp.GetToken() != "" {
		t.Error("a Root Token was returned without its audit event")
	}
}

// TestSecretsNeverLeak runs successful and failed Onboarding and
// inspection, and checks that no audit event or error message carries the
// Provider Credential, the bootstrap secret or a Service Token.
func TestSecretsNeverLeak(t *testing.T) {
	h := newHarness(t)

	root := h.onboard(t, onboardRequest())

	var errs []error

	wrongSecret := onboardRequest()
	wrongSecret.BootstrapSecret = bootstrapSecret + "x"

	badProvider := onboardRequest()
	badProvider.Provider = cfToken

	badType := onboardRequest()
	badType.Credential.Type = cfToken

	for _, req := range []*dnsgatev1.OnboardRequest{wrongSecret, badProvider, badType} {
		_, err := h.client.Onboard(t.Context(), req)
		errs = append(errs, err)
	}

	if _, err := h.client.InspectToken(t.Context(), root); err != nil {
		t.Fatal(err)
	}

	_, err := h.client.InspectToken(t.Context(), root+"x")
	errs = append(errs, err)

	secrets := []string{cfToken, bootstrapSecret, root}

	for _, s := range secrets {
		if strings.Contains(h.audit.String(), s) {
			t.Errorf("audit log contains a secret:\n%s", h.audit.String())
		}

		for _, err := range errs {
			if err == nil {
				t.Fatal("a failing request succeeded")
			}

			if strings.Contains(err.Error(), s) {
				t.Errorf("error %q contains a secret", err)
			}
		}
	}
}

func TestInspectNeverReturnsTheCredential(t *testing.T) {
	h := newHarness(t)

	got, err := h.client.InspectToken(t.Context(), h.onboard(t, onboardRequest()))
	if err != nil {
		t.Fatal(err)
	}

	wire, err := proto.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(wire, []byte(cfToken)) || strings.Contains(prototext.Format(got), cfToken) {
		t.Errorf("inspect response carries the Provider Credential: %v", got)
	}
}

func TestInspectRejectsInvalidOrExpiredTokens(t *testing.T) {
	h := newHarness(t)

	req := onboardRequest()
	req.Expires = durationpb.New(time.Hour)
	expiring := h.onboard(t, req)

	for name, tok := range map[string]string{
		"empty":    "",
		"garbage":  "not-a-token",
		"tampered": expiring[:len(expiring)-4] + "AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.client.InspectToken(t.Context(), tok)
			wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
		})
	}

	t.Run("expired", func(t *testing.T) {
		h.now = h.now.Add(time.Hour)

		_, err := h.client.InspectToken(t.Context(), expiring)
		wantError(t, err, codes.Unauthenticated, dnsgatev1.Error_CATEGORY_UNAUTHENTICATED)
	})

	denials := h.auditEvents(t)[1:]
	if len(denials) != 4 {
		t.Fatalf("audit events after onboard = %v, want 4 denials", denials)
	}

	for _, e := range denials {
		if e["event"] != "token.inspect" || e["result"] != "denied" || e["category"] != "unauthenticated" {
			t.Errorf("audit event = %v, want a denied token.inspect", e)
		}
	}
}

func TestCallRejectsStreamsWithoutARequest(t *testing.T) {
	for name, msgs := range map[string][]*dnsgatev1.CallRequest{
		"no message":   nil,
		"no request":   {{}},
		"no operation": {{Message: &dnsgatev1.CallRequest_Request{Request: &dnsgatev1.Request{}}}},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			stream, err := h.api.Call(t.Context())
			if err != nil {
				t.Fatal(err)
			}

			for _, m := range msgs {
				if err := stream.Send(m); err != nil {
					t.Fatal(err)
				}
			}

			if err := stream.CloseSend(); err != nil {
				t.Fatal(err)
			}

			_, err = stream.Recv()
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)
		})
	}
}

func TestOnboardRejectsUnsupportedProviderOrCredential(t *testing.T) {
	for name, edit := range map[string]func(*dnsgatev1.OnboardRequest){
		"unknown provider":        func(r *dnsgatev1.OnboardRequest) { r.Provider = "route53" },
		"missing provider":        func(r *dnsgatev1.OnboardRequest) { r.Provider = "" },
		"unknown credential type": func(r *dnsgatev1.OnboardRequest) { r.Credential.Type = "global-api-key" },
		"empty credential":        func(r *dnsgatev1.OnboardRequest) { r.Credential.Value = "" },
		"missing credential":      func(r *dnsgatev1.OnboardRequest) { r.Credential = nil },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			req := onboardRequest()
			edit(req)

			_, err := h.client.Onboard(t.Context(), req)
			wantError(t, err, codes.InvalidArgument, dnsgatev1.Error_CATEGORY_INVALID_REQUEST)
		})
	}
}
