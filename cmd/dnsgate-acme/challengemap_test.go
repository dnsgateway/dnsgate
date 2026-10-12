package main

import (
	"strings"
	"testing"
)

func TestDaemonRefusesAChallengeMapWithAnInvalidEntry(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		// want are what the error must name: the entry and its fault.
		want []string
	}{
		"key with a dot": {
			content: "example.com:\n  zone: example.com\n  name: _acme-challenge\n",
			want:    []string{`"example.com"`, "DNS label"},
		},
		"key with an underscore": {
			content: "_acme:\n  zone: example.com\n  name: _acme-challenge\n",
			want:    []string{`"_acme"`, "DNS label"},
		},
		"key starting with a hyphen": {
			content: "-examplecom:\n  zone: example.com\n  name: _acme-challenge\n",
			want:    []string{`"-examplecom"`, "DNS label"},
		},
		"key of 64 characters": {
			content: strings.Repeat("a", 64) + ":\n  zone: example.com\n  name: _acme-challenge\n",
			want:    []string{strings.Repeat("a", 64), "DNS label"},
		},
		"no zone and the apex": {
			content: "examplecom:\n  name: \"@\"\n",
			want:    []string{`"examplecom"`, "absolute"},
		},
		"no name": {
			content: "examplecom:\n  zone: example.com\n",
			want:    []string{`"examplecom"`, "name"},
		},
		"empty entry": {
			content: "examplecom: {}\n",
			want:    []string{`"examplecom"`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runCLI(t, "--listen", heldAddr(t), "--challenge-map", writeMap(t, "map.yaml", tc.content))
			if err == nil {
				t.Fatalf("the daemon started with an invalid Challenge Map\n%s", out)
			}

			for _, want := range append([]string{"Challenge Map"}, tc.want...) {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want one naming %s", err, want)
				}
			}
		})
	}
}
