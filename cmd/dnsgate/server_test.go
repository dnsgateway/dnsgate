package main

import (
	"net"
	"strings"
	"testing"
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
