package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsgate/internal/server/servertest"
)

// heldAddr returns an address something else listens on until the test
// ends, so a daemon that tried to listen before checking its flags would
// fail on the address instead.
func heldAddr(t *testing.T) string {
	t.Helper()

	held, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = held.Close() })

	return held.Addr().String()
}

func TestDaemonRefusesACertificateWithoutItsKeyOrTheReverse(t *testing.T) {
	cert, key := writeTLSFiles(t)
	addr := heldAddr(t)

	for name, args := range map[string][]string{
		"certificate only": {"--tls-cert-file", cert},
		"key only":         {"--tls-key-file", key},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runCLI(t, append([]string{"--listen", addr}, args...)...)
			if err == nil || !strings.Contains(err.Error(), "--tls-cert-file") || !strings.Contains(err.Error(), "--tls-key-file") {
				t.Errorf("error = %v, want one naming --tls-cert-file and --tls-key-file before it listens\n%s", err, out)
			}
		})
	}
}

func TestDaemonRefusesACertificateItCannotLoad(t *testing.T) {
	cert, _ := writeTLSFiles(t)

	out, err := runCLI(t, append(mapArgs(t), "--listen", heldAddr(t), "--tls-cert-file", cert, "--tls-key-file", cert)...)
	if err == nil || !strings.Contains(err.Error(), "TLS certificate") {
		t.Errorf("error = %v, want one about the TLS certificate before it listens\n%s", err, out)
	}
}

func TestDaemonTakesTLSFilesFromEnv(t *testing.T) {
	cert, key := writeTLSFiles(t)
	t.Setenv("DNSGATE_ACME_TLS_CERT_FILE", cert)
	t.Setenv("DNSGATE_ACME_TLS_KEY_FILE", key)

	d := startDaemon(t)

	checkEndpoints(t, httpsClient(t, cert, tls.VersionTLS13), "https://"+d.Addr)
}

func TestDaemonTakesListenAddressFromEnv(t *testing.T) {
	addr := servertest.FreePort(t)
	t.Setenv("DNSGATE_ACME_LISTEN_ADDRESS", addr)

	servertest.LaunchAt(t, addr, daemonCmd(t, nil))

	checkEndpoints(t, &http.Client{}, "http://"+addr)
}

func TestDaemonRefusesToStartWithAnUnknownLogLevel(t *testing.T) {
	out, err := runCLI(t, "--listen", heldAddr(t), "--log-level", "verbose")
	if err == nil || !strings.Contains(err.Error(), `"verbose"`) || !strings.Contains(err.Error(), "error, warn, info, debug") {
		t.Errorf("error = %v, want one naming the level and the accepted levels before it listens\n%s", err, out)
	}
}

func TestDaemonLogsDebugLinesOnlyAtDebug(t *testing.T) {
	for level, want := range map[string]bool{"debug": true, "info": false} {
		t.Run(level, func(t *testing.T) {
			logs := startDaemon(t, "--log-level", level).Logs.String()
			if got := strings.Contains(logs, `"level":"DEBUG"`); got != want {
				t.Errorf("logs at %s have a debug line = %v, want %v:\n%s", level, got, want, logs)
			}
		})
	}
}

func TestDaemonStopsCleanlyWhenItsContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	var logs servertest.SyncBuffer

	cmd := newRootCmd()
	cmd.SetErr(&logs)
	cmd.SetArgs(append(mapArgs(t), "--listen", "127.0.0.1:0"))

	done := make(chan error, 1)

	go func() { done <- cmd.ExecuteContext(ctx) }()

	for deadline := time.Now().Add(10 * time.Second); !strings.Contains(logs.String(), `"msg":"serving"`); {
		if time.Now().After(deadline) {
			t.Fatalf("daemon is not serving:\n%s", logs.String())
		}

		time.Sleep(10 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("daemon stopped with %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop after its context was canceled")
	}

	if !strings.Contains(logs.String(), `"msg":"stopped"`) {
		t.Errorf("daemon did not log that it stopped:\n%s", logs.String())
	}
}

func TestHelpDocumentsTheDaemonFlags(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}

	for _, want := range []string{
		"(env DNSGATE_ACME_LISTEN_ADDRESS)", `(default ":8080")`,
		"(env DNSGATE_ACME_TLS_CERT_FILE)", "(env DNSGATE_ACME_TLS_KEY_FILE)",
		"error, warn, info, debug (env DNSGATE_ACME_LOG_LEVEL)", `(default "info")`,
		"(env DNSGATE_ACME_CHALLENGE_MAP)", "(env DNSGATE_ACME_TTL) (default 60)",
		"(env DNSGATE_GATEWAY)", `(default "localhost:8443")`,
		"(env DNSGATE_CA_FILE, a path list)", "env DNSGATE_EGRESS)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help does not contain %q:\n%s", want, out)
		}
	}
}

// The help tells an Administrator how to configure an acmeproxy client:
// the calls, how to authenticate to them, and that the fqdn bypasses the
// Challenge Map.
func TestHelpDescribesTheAcmeproxyAPI(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}

	for _, want := range []string{
		"serves the acme-dns and acmeproxy APIs",
		"POST /present adds the challenge value at the fqdn",
		"POST /cleanup removes that value only",
		"HTTP Basic auth: the username is the token's jti and the password is the Service Token",
		"The fqdn is the Challenge Target: the Challenge Map is not consulted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help does not contain %q:\n%s", want, out)
		}
	}
}

// Without a Challenge Map, every subdomain is unmapped: /update takes it
// as the certificate domain (ADR 0012). /present never consults the map.
func TestDaemonStartsWithoutAChallengeMap(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge", "_acme-challenge.**"}))

	t.Setenv("DNSGATE_ACME_CHALLENGE_MAP", "")

	// Not daemonCmd, which gives a --challenge-map.
	gw := servertest.Launch(t, commandRun([]string{"--listen", "127.0.0.1:0", "--gateway", e.Gateway.Addr, "--ca-file", e.Env.CAFile}))

	d := &acmeDaemon{Base: "http://" + gw.Addr, HTTP: &http.Client{}, Logs: gw.Logs}
	d.wantUpdated(t, tok, "www.example.com", challenge(1))
	d.wantPresented(t, tok, "_acme-challenge.api.example.com.", challenge(2))

	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.www.example.com", `60 "`+challenge(1)+`"`)
	e.wantTXT(t, zoneComID, zoneCom, "_acme-challenge.api.example.com", `60 "`+challenge(2)+`"`)
}

func TestHelpPresentsTheChallengeMapAsOptional(t *testing.T) {
	out, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}

	var help string

	for line := range strings.SplitSeq(out, "\n") {
		if strings.Contains(line, "--challenge-map") {
			help = line
		}
	}

	if !strings.Contains(help, "without it, every subdomain is unmapped") {
		t.Errorf("--challenge-map help = %q, want it to say that without a map every subdomain is unmapped\n%s", help, out)
	}

	if strings.Contains(help, "required") {
		t.Errorf("help presents the Challenge Map as required: %q", help)
	}
}

func TestDaemonRefusesAChallengeMapItCannotRead(t *testing.T) {
	for name, file := range map[string]string{
		"missing":       filepath.Join(t.TempDir(), "absent.yaml"),
		"not a map":     writeMap(t, "list.yaml", "- examplecom\n"),
		"unknown field": writeMap(t, "typo.yaml", "examplecom:\n  zone: example.com\n  target: _acme-challenge\n"),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runCLI(t, "--listen", heldAddr(t), "--challenge-map", file)
			if err == nil || !strings.Contains(err.Error(), "Challenge Map") {
				t.Errorf("error = %v, want one about the Challenge Map before it listens\n%s", err, out)
			}
		})
	}
}

func TestDaemonTakesTheChallengeMapFromEnv(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))

	t.Setenv("DNSGATE_ACME_CHALLENGE_MAP", writeMap(t, "env.yaml", "fromenv:\n  zone: example.com\n  name: _acme-challenge\n"))

	// Not daemonCmd, whose --challenge-map would replace the environment's.
	gw := servertest.Launch(t, commandRun([]string{"--listen", "127.0.0.1:0", "--gateway", e.Gateway.Addr, "--ca-file", e.Env.CAFile}))

	d := &acmeDaemon{Base: "http://" + gw.Addr, HTTP: &http.Client{}, Logs: gw.Logs}
	d.wantUpdated(t, tok, "fromenv", challenge(1))
}

func TestDaemonRefusesAnInvalidTTLFromEnvUnlessTheFlagReplacesIt(t *testing.T) {
	t.Setenv("DNSGATE_ACME_TTL", "1m")

	out, err := runCLI(t, append(mapArgs(t), "--listen", heldAddr(t))...)
	if err == nil || !strings.Contains(err.Error(), "DNSGATE_ACME_TTL") || !strings.Contains(err.Error(), `"1m"`) {
		t.Errorf("error = %v, want one naming DNSGATE_ACME_TTL and its value before it listens\n%s", err, out)
	}

	startDaemon(t, "--ttl", "90")
}

func TestDaemonTakesTheGatewayFromEnv(t *testing.T) {
	e := newE2E(t)
	tok := e.token(t, patchTXT("example.com", []string{"_acme-challenge"}))

	t.Setenv("DNSGATE_GATEWAY", e.Gateway.Addr)
	t.Setenv("DNSGATE_CA_FILE", e.Env.CAFile)

	gw := startDaemon(t)

	d := &acmeDaemon{Base: "http://" + gw.Addr, HTTP: &http.Client{}, Logs: gw.Logs}
	d.wantUpdated(t, tok, "examplecom", challenge(1))
}
