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
