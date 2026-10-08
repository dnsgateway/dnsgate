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

	cmd.AddCommand(newTokenInspectCmd(flags))

	return cmd
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
