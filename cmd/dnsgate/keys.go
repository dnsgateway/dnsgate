package main

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/dnsgateway/dnsgate/internal/keys"
)

func newKeysCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage the Gateway's signing and encryption keys",
	}

	cmd.AddCommand(newKeysGenerateCmd(flags))

	return cmd
}

func newKeysGenerateCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Write a new signing and encryption key pair",
		Long: "Write an Ed25519 signing key pair (kid sig-<suffix>) and an X25519 encryption key pair " +
			"(kid enc-<suffix>) as PEM files readable only by their owner. Existing files are never overwritten.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runKeysGenerate(cmd.OutOrStdout(), flags, time.Now())
		},
	}

	flags.AddKeysGenerateFlags(cmd.Flags())

	return cmd
}

func runKeysGenerate(out io.Writer, f *Flags, now time.Time) error {
	suffix := f.KeyIDSuffix
	if suffix == "" {
		suffix = now.UTC().Format("2006-01")
	}

	gen, err := keys.Generate(f.KeyDir, suffix)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(out, "signing key ID:    %s\nencryption key ID: %s\n", gen.SigningKeyID, gen.EncryptionKeyID); err != nil {
		return err
	}

	for _, path := range gen.Files {
		if _, err := fmt.Fprintf(out, "wrote %s\n", path); err != nil {
			return err
		}
	}

	return nil
}
