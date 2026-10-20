// Package loglevel names the log levels a daemon's --log-level accepts.
package loglevel

import (
	"errors"
	"log/slog"
	"strings"
)

// levels are the accepted log levels and their slog levels, most severe
// first.
var levels = []struct {
	name  string
	level slog.Level
}{
	{"error", slog.LevelError},
	{"warn", slog.LevelWarn},
	{"info", slog.LevelInfo},
	{"debug", slog.LevelDebug},
}

// Names returns the accepted log levels, most severe first.
func Names() string {
	names := make([]string, len(levels))
	for i, l := range levels {
		names[i] = l.name
	}

	return strings.Join(names, ", ")
}

// Value is a --log-level flag: a pflag.Value that takes one of Names and
// sets the slog level it points at.
type Value struct {
	level *slog.Level
}

// NewValue returns the Value that sets level, whose current value is the
// flag's default.
func NewValue(level *slog.Level) *Value {
	return &Value{level: level}
}

// Set sets the level that name names.
func (v *Value) Set(name string) error {
	for _, l := range levels {
		if l.name == name {
			*v.level = l.level

			return nil
		}
	}

	return errors.New("unknown log level: use " + Names())
}

// String returns the name of the level.
func (v *Value) String() string {
	for _, l := range levels {
		if l.level == *v.level {
			return l.name
		}
	}

	return v.level.String()
}

// Type is "string", so the help shows a --log-level as one.
func (v *Value) Type() string {
	return "string"
}
