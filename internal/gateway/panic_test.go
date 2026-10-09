package gateway_test

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

// panickingProviders returns the Providers of fake, as "cloudflare",
// whose Factory panics, while panicking is set, with a message quoting
// what it builds from: the Provider Credential.
func panickingProviders(fake *providertest.Provider, panicking *atomic.Bool) dnsprovider.Registry {
	f := fake.Factory()
	build := f.New
	f.New = func(fields map[string]string, opts ...dnsprovider.Option) (dnsprovider.Provider, error) {
		if panicking.Load() {
			panic(fmt.Sprintf("building a provider from %v", fields))
		}

		return build(fields, opts...)
	}

	return dnsprovider.Registry{"cloudflare": f}
}

// newPanickingHarness returns a harness, with its zones, whose Gateway's
// Provider panics while the returned flag is set, and a Root Token
// onboarded before it does.
func newPanickingHarness(t *testing.T) (h *harness, panicking *atomic.Bool, root string) {
	t.Helper()

	h = newHarness(t)
	h.addZones()

	panicking = &atomic.Bool{}
	h.providers = panickingProviders(h.fake, panicking)
	h.serve(t, h.keys)

	return h, panicking, h.onboard(t, onboardRequest())
}

// panickingWriter is an audit log that panics, while panicking is set,
// with a message quoting the Bootstrap Secret.
type panickingWriter struct {
	panicking atomic.Bool
	buf       syncBuffer
}

func (w *panickingWriter) Write(p []byte) (int, error) {
	if w.panicking.Load() {
		panic("audit log refused, bootstrap secret " + bootstrapSecret)
	}

	return w.buf.Write(p)
}

func TestAPanicInARequestIsAnInternalErrorAndTheGatewayKeepsServing(t *testing.T) {
	h, panicking, root := newPanickingHarness(t)

	panicking.Store(true)

	_, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root})
	wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

	if msg := status.Convert(err).Message(); msg != "internal error" {
		t.Errorf("error message = %q, want %q", msg, "internal error")
	}

	panicking.Store(false)

	if _, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root}); err != nil {
		t.Errorf("ListZones after a panic: %v", err)
	}
}

// TestAPanicLeaksNoSecret panics while handling requests that carry the
// Service Token, the Provider Credential and the Bootstrap Secret, with
// panic values that quote them, and checks that neither the client's
// error, the logs nor the audit log carry any of them.
func TestAPanicLeaksNoSecret(t *testing.T) {
	for name, panicIn := range map[string]func(t *testing.T) (*harness, string, error){
		"building the Provider": func(t *testing.T) (*harness, string, error) {
			h, panicking, root := newPanickingHarness(t)

			panicking.Store(true)

			_, err := h.client.ListZones(t.Context(), &dnsgatev1.ListZonesRequest{Token: root})

			return h, root, err
		},
		"auditing Onboarding": func(t *testing.T) (*harness, string, error) {
			w := &panickingWriter{}
			w.panicking.Store(true)

			h := newHarnessAuditingTo(t, w)
			h.audit = &w.buf

			_, err := h.client.Onboard(t.Context(), onboardRequest())

			return h, "", err
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, serviceToken, err := panicIn(t)
			wantError(t, err, codes.Internal, dnsgatev1.Error_CATEGORY_INTERNAL)

			logs := h.logs.String()
			if !strings.Contains(logs, `"msg":"request panicked"`) {
				t.Errorf("logs =\n%s\nwant the panic", logs)
			}

			secrets := map[string]string{"Bootstrap Secret": bootstrapSecret, "Provider Credential": cfToken}
			if serviceToken != "" {
				secrets["Service Token"] = serviceToken
			}

			for name, secret := range secrets {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q carries the %s", err, name)
				}

				if strings.Contains(logs, secret) {
					t.Errorf("logs carry the %s:\n%s", name, logs)
				}

				if strings.Contains(h.audit.String(), secret) {
					t.Errorf("audit log carries the %s:\n%s", name, h.audit.String())
				}
			}
		})
	}
}
