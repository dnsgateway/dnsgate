package main

import (
	"io"
	"log/slog"
	"os"
	"reflect"
	"testing"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/acme"
)

// configure parses args as the daemon does, with env as the environment,
// and returns the ACME Endpoint's options they give.
func configure(args []string, env map[string]string) (acme.Options, error) {
	flags := pflag.NewFlagSet(bin, pflag.ContinueOnError)
	flags.SetOutput(io.Discard)

	options := daemonFlags(flags)

	if err := flags.Parse(args); err != nil {
		return acme.Options{}, flagError(err)
	}

	return options(func(key string) (string, bool) {
		v, ok := env[key]

		return v, ok
	})
}

func TestDaemonFlagsGiveTheOptions(t *testing.T) {
	defaults := func(change func(o *acme.Options)) acme.Options {
		o := acme.Options{Listen: ":8080", TTL: 60, LogLevel: slog.LevelInfo, Gateway: "localhost:8443"}
		change(&o)

		return o
	}

	pathList := func(paths ...string) string {
		var list string

		for i, p := range paths {
			if i > 0 {
				list += string(os.PathListSeparator)
			}

			list += p
		}

		return list
	}

	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		want acme.Options
	}{
		"built-in defaults": {
			want: defaults(func(*acme.Options) {}),
		},
		"flags": {
			args: []string{
				"--listen", "127.0.0.1:9090", "--tls-cert-file", "c.pem", "--tls-key-file", "k.pem",
				"--challenge-map", "map.yaml", "--ttl", "90", "--log-level", "debug",
				"--gateway", "gw:443", "--ca-file", "a.pem", "--ca-file", "b.pem", "--egress", "agent",
			},
			want: acme.Options{
				Listen: "127.0.0.1:9090", CertFile: "c.pem", KeyFile: "k.pem",
				ChallengeMapFile: "map.yaml", TTL: 90, LogLevel: slog.LevelDebug,
				Gateway: "gw:443", CAFiles: []string{"a.pem", "b.pem"}, Egress: dnsgatev1.Egress_EGRESS_AGENT,
			},
		},
		"environment": {
			env: map[string]string{
				"DNSGATE_ACME_LISTEN_ADDRESS": "127.0.0.1:9090", "DNSGATE_ACME_TLS_CERT_FILE": "c.pem",
				"DNSGATE_ACME_TLS_KEY_FILE": "k.pem", "DNSGATE_ACME_CHALLENGE_MAP": "map.yaml",
				"DNSGATE_ACME_TTL": "90", "DNSGATE_ACME_LOG_LEVEL": "debug",
				"DNSGATE_GATEWAY": "gw:443", "DNSGATE_CA_FILE": pathList("a.pem", "b.pem"), "DNSGATE_EGRESS": "agent",
			},
			want: acme.Options{
				Listen: "127.0.0.1:9090", CertFile: "c.pem", KeyFile: "k.pem",
				ChallengeMapFile: "map.yaml", TTL: 90, LogLevel: slog.LevelDebug,
				Gateway: "gw:443", CAFiles: []string{"a.pem", "b.pem"}, Egress: dnsgatev1.Egress_EGRESS_AGENT,
			},
		},
		"flags over environment": {
			args: []string{"--ttl", "90", "--gateway", "flag:443", "--ca-file", "flag.pem", "--egress", "gateway"},
			env: map[string]string{
				"DNSGATE_ACME_TTL": "30", "DNSGATE_GATEWAY": "env:443",
				"DNSGATE_CA_FILE": pathList("a.pem", "b.pem"), "DNSGATE_EGRESS": "agent",
			},
			want: defaults(func(o *acme.Options) {
				o.TTL, o.Gateway, o.CAFiles, o.Egress = 90, "flag:443", []string{"flag.pem"}, dnsgatev1.Egress_EGRESS_GATEWAY
			}),
		},
		"bad environment values replaced by their flags": {
			args: []string{"--ttl", "90", "--log-level", "warn", "--egress", "agent"},
			env:  map[string]string{"DNSGATE_ACME_TTL": "1m", "DNSGATE_ACME_LOG_LEVEL": "verbose", "DNSGATE_EGRESS": "relay"},
			want: defaults(func(o *acme.Options) {
				o.TTL, o.LogLevel, o.Egress = 90, slog.LevelWarn, dnsgatev1.Egress_EGRESS_AGENT
			}),
		},
		"CA path list without its empty entries": {
			env:  map[string]string{"DNSGATE_CA_FILE": pathList("", "a.pem", "", "b.pem", "")},
			want: defaults(func(o *acme.Options) { o.CAFiles = []string{"a.pem", "b.pem"} }),
		},
		"empty CA path list": {
			env:  map[string]string{"DNSGATE_CA_FILE": ""},
			want: defaults(func(*acme.Options) {}),
		},
		// The TLS pair is acme.Run's to check.
		"certificate without its key": {
			args: []string{"--tls-cert-file", "c.pem"},
			want: defaults(func(o *acme.Options) { o.CertFile = "c.pem" }),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := configure(tc.args, tc.env)
			if err != nil {
				t.Fatalf("configure: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("options = %+v\nwant      %+v", got, tc.want)
			}
		})
	}
}

func TestDaemonFlagsRefuseBadValues(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"TTL flag": {
			args: []string{"--ttl", "1m"},
			want: `invalid argument "1m" for "--ttl" flag: give the TTL in seconds`,
		},
		"TTL env": {
			env:  map[string]string{"DNSGATE_ACME_TTL": "1m"},
			want: `DNSGATE_ACME_TTL "1m": give the TTL in seconds`,
		},
		"empty TTL env": {
			env:  map[string]string{"DNSGATE_ACME_TTL": ""},
			want: `DNSGATE_ACME_TTL "": give the TTL in seconds`,
		},
		"log level flag": {
			args: []string{"--log-level", "verbose"},
			want: `invalid argument "verbose" for "--log-level" flag: unknown log level: use error, warn, info, debug`,
		},
		"log level env": {
			env:  map[string]string{"DNSGATE_ACME_LOG_LEVEL": "verbose"},
			want: `DNSGATE_ACME_LOG_LEVEL "verbose": unknown log level: use error, warn, info, debug`,
		},
		// --egress keeps the message dnsgate-cli gives, which names the value.
		"egress flag": {
			args: []string{"--egress", "relay"},
			want: `unknown egress "relay": use gateway or agent`,
		},
		"egress env": {
			env:  map[string]string{"DNSGATE_EGRESS": "relay"},
			want: `unknown egress "relay": use gateway or agent`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configure(tc.args, tc.env)
			if err == nil || err.Error() != tc.want {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
