package main

import "github.com/spf13/pflag"

// Flags holds the parsed values of the CLI flags. Later commands add the
// Gateway address and Service Token here, each falling back to an
// environment variable.
type Flags struct{}

// DefaultFlags builds Flags from environment variables or defaults, before
// any flag is parsed, so flags override the environment.
func DefaultFlags() *Flags {
	return &Flags{}
}

// AddPersistentFlags registers the flags every subcommand inherits.
func (f *Flags) AddPersistentFlags(_ *pflag.FlagSet) {}
