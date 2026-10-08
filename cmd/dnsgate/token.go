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

// inspectOutput is what "token inspect" prints.
type inspectOutput struct {
	Sub         string             `json:"sub"`
	Jti         string             `json:"jti"`
	Ancestors   []string           `json:"ancestors"`
	IssuedAt    time.Time          `json:"iat"`
	NotBefore   time.Time          `json:"nbf"`
	Expiry      *time.Time         `json:"exp"`
	Provider    string             `json:"provider"`
	Permissions []permissionOutput `json:"permissions"`
}

type permissionOutput struct {
	Verbs     []string `json:"verbs,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Zones     []string `json:"zones,omitempty"`
	Names     []string `json:"names,omitempty"`
	Types     []string `json:"types,omitempty"`
	Egress    []string `json:"egress,omitempty"`
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
		Permissions: make([]permissionOutput, 0, len(resp.GetPermissions())),
	}

	if o.Ancestors == nil {
		o.Ancestors = []string{}
	}

	if resp.Exp != nil {
		exp := resp.GetExp().AsTime()
		o.Expiry = &exp
	}

	for _, p := range resp.GetPermissions() {
		o.Permissions = append(o.Permissions, permissionOutput{
			Verbs:     p.GetVerbs(),
			Resources: p.GetResources(),
			Zones:     p.GetZones(),
			Names:     p.GetNames(),
			Types:     p.GetTypes(),
			Egress:    p.GetEgress(),
		})
	}

	return o
}
