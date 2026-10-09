package main

import (
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
