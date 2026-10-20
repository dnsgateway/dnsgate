package loglevel_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/dnsgateway/dnsgate/internal/loglevel"
)

func TestNamesListsTheLevelsMostSevereFirst(t *testing.T) {
	if got, want := loglevel.Names(), "error, warn, info, debug"; got != want {
		t.Errorf("Names() = %q, want %q", got, want)
	}
}

func TestValueResolvesEachNameToItsLevel(t *testing.T) {
	for name, want := range map[string]slog.Level{
		"error": slog.LevelError,
		"warn":  slog.LevelWarn,
		"info":  slog.LevelInfo,
		"debug": slog.LevelDebug,
	} {
		level := slog.LevelError + 1

		v := loglevel.NewValue(&level)
		if err := v.Set(name); err != nil || level != want || v.String() != name {
			t.Errorf("Set(%q) = %v: level %v, String %q; want %v", name, err, level, v.String(), want)
		}
	}
}

func TestValueRefusesAnUnknownName(t *testing.T) {
	level := slog.LevelWarn

	err := loglevel.NewValue(&level).Set("verbose")
	if err == nil || err.Error() != "unknown log level: use error, warn, info, debug" {
		t.Errorf("Set(verbose) error = %v", err)
	}

	if level != slog.LevelWarn {
		t.Errorf("Set(verbose) changed the level to %v", level)
	}
}

// The help shows a --log-level as a string with its default quoted.
func TestValueIsAStringFlag(t *testing.T) {
	level := slog.LevelInfo

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Var(loglevel.NewValue(&level), "log-level", "lowest level")

	if usage := flags.FlagUsages(); !strings.Contains(usage, `--log-level string   lowest level (default "info")`) {
		t.Errorf("usage = %q", usage)
	}
}
