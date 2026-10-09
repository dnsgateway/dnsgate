package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/revocation"
)

func TestServerLogsDebugLinesAtDebug(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config, "--log-level", "debug")

	logs := gw.logs.String()
	if !strings.Contains(logs, `"level":"DEBUG"`) || !strings.Contains(logs, `"msg":"serving"`) {
		t.Errorf("server logs at debug have no debug line or no serving line:\n%s", logs)
	}
}

func TestServerLogsAtInfoByDefault(t *testing.T) {
	env := newGatewayEnv(t)
	gw := startServer(t, env.config)

	logs := gw.logs.String()
	if strings.Contains(logs, `"level":"DEBUG"`) || !strings.Contains(logs, `"msg":"serving"`) {
		t.Errorf("server logs by default have a debug line or no serving line:\n%s", logs)
	}
}

func TestServerTakesLogLevelFromEnvUnlessTheFlagIsSet(t *testing.T) {
	t.Setenv("DNSGATE_LOG_LEVEL", "debug")

	env := newGatewayEnv(t)

	if logs := startServer(t, env.config).logs.String(); !strings.Contains(logs, `"level":"DEBUG"`) {
		t.Errorf("server logs with DNSGATE_LOG_LEVEL=debug have no debug line:\n%s", logs)
	}

	if logs := startServer(t, env.config, "--log-level", "info").logs.String(); strings.Contains(logs, `"level":"DEBUG"`) {
		t.Errorf("server logs with --log-level info over DNSGATE_LOG_LEVEL=debug have a debug line:\n%s", logs)
	}
}

func TestServerHelpDocumentsTheLogLevel(t *testing.T) {
	out, err := runCLI(t, "server", "--help")
	if err != nil {
		t.Fatalf("server --help: %v", err)
	}

	if !strings.Contains(out, "Logs below --log-level are dropped; audit events are always written.") {
		t.Errorf("server help does not say what --log-level drops:\n%s", out)
	}

	if !strings.Contains(out, "At debug, each request is logged when it ends, with its gRPC method, operation, request ID, peer address, duration and gRPC code.") {
		t.Errorf("server help does not say that debug logs each request:\n%s", out)
	}

	if !strings.Contains(out, "error, warn, info, debug (env DNSGATE_LOG_LEVEL)") || !strings.Contains(out, `(default "info")`) {
		t.Errorf("server help does not list the log levels, DNSGATE_LOG_LEVEL and the default:\n%s", out)
	}
}

func TestServerRefusesToStartWithAnUnknownLogLevel(t *testing.T) {
	// Something else holds the configured address, so a server that tried
	// to listen before checking the level would fail on the address instead.
	held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = held.Close() })

	env := newGatewayEnvAt(t, held.Addr().String())

	out, err := runCLI(t, "server", "--config", env.config, "--log-level", "verbose")
	if err == nil || !strings.Contains(err.Error(), `"verbose"`) || !strings.Contains(err.Error(), "error, warn, info, debug") {
		t.Errorf("server error = %v, want one naming the level and the accepted levels before it listens\n%s", err, out)
	}
}

func TestServerLogsEachRequestAtDebugOnly(t *testing.T) {
	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	for level, want := range map[string]bool{"debug": true, "info": false} {
		t.Run(level, func(t *testing.T) {
			env := newGatewayEnvAt(t, freePort(t))
			gw := startServerAt(t, env, "--log-level", level)

			if _, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare"); err != nil {
				t.Fatalf("onboard: %v", err)
			}

			logs := gw.logs.String()

			logged := strings.Contains(logs, `"msg":"request"`) && strings.Contains(logs, `"operation":"onboard"`) &&
				strings.Contains(logs, `"code":"OK"`) && strings.Contains(logs, `"peer":"127.0.0.1:`)
			if logged != want {
				t.Errorf("server logs at %s: request line logged = %v, want %v:\n%s", level, logged, want, logs)
			}
		})
	}
}

func TestServerAtErrorDropsInfoLinesButStillAudits(t *testing.T) {
	env := newGatewayEnvAt(t, freePort(t))
	gw := startServerAt(t, env, "--log-level", "error")

	t.Setenv("DNSGATE_BOOTSTRAP_SECRET", testBootstrapSecret)
	t.Setenv("DNSGATE_PROVIDER_CREDENTIAL", testCFToken)

	if _, err := runClient(t, env, gw, "onboard", "--provider", "cloudflare"); err != nil {
		t.Fatalf("onboard: %v", err)
	}

	if logs := gw.logs.String(); strings.Contains(logs, `"msg":"serving"`) || strings.Contains(logs, `"level":"INFO"`) {
		t.Errorf("server logs at error have info lines:\n%s", logs)
	}

	if audit := gw.audit.String(); !strings.Contains(audit, `"event":"onboard"`) {
		t.Errorf("server audit output at error has no onboard event:\n%s", audit)
	}
}

func TestRunningServerPurgesAnEntryOnceItsTokenExpires(t *testing.T) {
	saved := purgeInterval
	purgeInterval = 10 * time.Millisecond

	t.Cleanup(func() { purgeInterval = saved })

	env := newGatewayEnv(t)

	store, err := revocation.OpenSQLite(t.Context(), filepath.Join(env.dir, "dnsgate.db"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })

	// Not yet expired when the server starts, so the startup purge keeps it.
	for id, exp := range map[string]time.Time{"tok_SOON": time.Now().Add(2 * time.Second), "tok_FOREVER": {}} {
		if err := store.Revoke(t.Context(), revocation.Entry{ID: id, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}

	startServer(t, env.config)

	revoked := func(id string) bool {
		t.Helper()

		got, err := store.AnyRevoked(t.Context(), []string{id})
		if err != nil {
			t.Fatal(err)
		}

		return got
	}

	if !revoked("tok_SOON") {
		t.Fatal("an entry was purged before its token expired")
	}

	for deadline := time.Now().Add(10 * time.Second); revoked("tok_SOON"); {
		if time.Now().After(deadline) {
			t.Fatal("the running server did not purge an entry whose token expired")
		}

		time.Sleep(10 * time.Millisecond)
	}

	if !revoked("tok_FOREVER") {
		t.Error("the running server purged an entry kept forever")
	}
}

func TestServerPurgesExpiredEntriesAtStartup(t *testing.T) {
	env := newGatewayEnv(t)

	store, err := revocation.OpenSQLite(t.Context(), filepath.Join(env.dir, "dnsgate.db"))
	if err != nil {
		t.Fatal(err)
	}

	for id, exp := range map[string]time.Time{
		"tok_EXPIRED": time.Now().Add(-time.Hour),
		"tok_LATER":   time.Now().Add(time.Hour),
		"tok_FOREVER": {},
	} {
		if err := store.Revoke(t.Context(), revocation.Entry{ID: id, ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	startServer(t, env.config)

	store, err = revocation.OpenSQLite(t.Context(), filepath.Join(env.dir, "dnsgate.db"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })

	for id, want := range map[string]bool{"tok_EXPIRED": false, "tok_LATER": true, "tok_FOREVER": true} {
		got, err := store.AnyRevoked(t.Context(), []string{id})
		if err != nil {
			t.Fatal(err)
		}

		if got != want {
			t.Errorf("%s revoked after the server started = %v, want %v", id, got, want)
		}
	}
}
