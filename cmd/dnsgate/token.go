package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
)

func newTokenCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Work with Service Tokens",
	}

	cmd.AddCommand(
		newTokenInspectCmd(flags),
		newTokenResealCmd(flags),
	)

	return cmd
}

func newTokenResealCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reseal [TOKEN]",
		Short: "Reseal a Service Token under the Gateway's current encryption key",
		Long: "Send a Service Token to the Gateway and print it resealed: re-encrypted under the Gateway's " +
			"current encryption key, with the same ID, Service Account, Permissions, expiry and signature. " +
			"Reseal tokens after the encryption key is rotated, before the old key's retirement deadline.\n\n" +
			"The token is TOKEN or, if left out, --" + flagToken + ". The token itself authorizes the request. " +
			"Prefer " + envToken + ": a token argument shows in process listings.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTokenReseal(cmd.Context(), cmd.OutOrStdout(), flags, args)
		},
	}

	flags.AddTokenFlags(cmd.Flags())
	flags.AddClientFlags(cmd.Flags())

	return cmd
}

func runTokenReseal(ctx context.Context, out io.Writer, f *Flags, args []string) error {
	tok := f.Token
	if len(args) == 1 {
		tok = args[0]
	}

	if tok == "" {
		return errors.New("no Service Token: give TOKEN or set " + envToken + " or --" + flagToken)
	}

	c, closeConn, err := dialGateway(f)
	if err != nil {
		return err
	}

	defer closeConn()

	resp, err := c.ResealToken(ctx, tok)
	if err != nil {
		return fmt.Errorf("reseal: %w", err)
	}

	_, err = fmt.Fprintln(out, resp.GetToken())

	return err
}

func newTokenInspectCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Show what a Service Token allows",
		Long: "Present a Service Token to the Gateway and print, as JSON, its Service Account (sub), " +
			"ID (jti), ancestors, lifetime, Provider and Permissions. The Provider Credential is never shown.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTokenInspect(cmd.Context(), cmd.OutOrStdout(), flags)
		},
	}

	flags.AddTokenFlags(cmd.Flags())
	flags.AddClientFlags(cmd.Flags())

	return cmd
}

// inspectOutput is what "token inspect" prints. Permissions are printed
// as the API messages: their generated JSON tags name each filter and
// leave out an empty one.
type inspectOutput struct {
	Sub         string                  `json:"sub"`
	Jti         string                  `json:"jti"`
	Ancestors   []string                `json:"ancestors"`
	IssuedAt    time.Time               `json:"iat"`
	NotBefore   time.Time               `json:"nbf"`
	Expiry      *time.Time              `json:"exp"`
	Provider    string                  `json:"provider"`
	Permissions []*dnsgatev1.Permission `json:"permissions"`
}

func runTokenInspect(ctx context.Context, out io.Writer, f *Flags) error {
	if f.Token == "" {
		return errors.New("no Service Token: set " + envToken + " or --" + flagToken)
	}

	c, closeConn, err := dialGateway(f)
	if err != nil {
		return err
	}

	defer closeConn()

	resp, err := c.InspectToken(ctx, f.Token)
	if err != nil {
		return fmt.Errorf("inspect: %w", err)
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	return enc.Encode(newInspectOutput(resp))
}

func newInspectOutput(resp *dnsgatev1.InspectTokenResponse) inspectOutput {
	o := inspectOutput{
		Sub:         resp.GetSub(),
		Jti:         resp.GetJti(),
		Ancestors:   resp.GetAncestors(),
		IssuedAt:    resp.GetIat().AsTime(),
		NotBefore:   resp.GetNbf().AsTime(),
		Provider:    resp.GetProvider(),
		Permissions: resp.GetPermissions(),
	}

	if o.Ancestors == nil {
		o.Ancestors = []string{}
	}

	if o.Permissions == nil {
		o.Permissions = []*dnsgatev1.Permission{}
	}

	if resp.Exp != nil {
		exp := resp.GetExp().AsTime()
		o.Expiry = &exp
	}

	return o
}
