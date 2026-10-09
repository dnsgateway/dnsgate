package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/durationpb"
	"sigs.k8s.io/yaml"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
	"github.com/dnsgateway/dnsgate/internal/token"
)

func newTokenCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Work with Service Tokens",
	}

	cmd.AddCommand(
		newTokenCreateCmd(flags),
		newTokenInspectCmd(flags),
		newTokenResealCmd(flags),
		newTokenRevokeCmd(flags),
	)

	return cmd
}

func newTokenCreateCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Issue a Derived Token for a client",
		Long: "Present a Parent Token, --" + flagToken + " or " + envToken + ", and print the Derived Token the Gateway " +
			"issues for the Service Account --" + flagSub + ". The Parent Token needs create on tokens. The Derived " +
			"Token gets the Parent Token's Provider Credential, which never leaves the Gateway.\n\n" +
			"--" + flagPermissions + " names a YAML or JSON file of Permissions, each with verbs:\n\n" +
			"  permissions:\n" +
			"    - verbs: [get, list, create, update, patch, delete]\n" +
			"      resources: [records]\n" +
			"      zones: [example.com]\n" +
			"      names: [\"**.apps\"]\n" +
			"      types: [A, AAAA, TXT]\n" +
			"      egress: [gateway, agent]\n\n" +
			"A filter left out means any; resources left out means [records]. The Derived Token must not exceed the " +
			"Parent Token: its Permissions must be covered by the Parent Token's, and it must expire no later.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTokenCreate(cmd.Context(), cmd.OutOrStdout(), flags)
		},
	}

	flags.AddTokenCreateFlags(cmd.Flags())

	return cmd
}

func runTokenCreate(ctx context.Context, out io.Writer, f *Flags) error {
	if err := checkTokenCreateFlags(f); err != nil {
		return err
	}

	perms, err := readPermissionsFile(f.PermissionsFile)
	if err != nil {
		return err
	}

	req := &dnsgatev1.CreateTokenRequest{Token: f.Token, Sub: f.Sub, Permissions: perms}
	if f.Expires != 0 {
		req.Expires = durationpb.New(f.Expires)
	}

	resp, err := callGateway(ctx, f, "token create", (*client.Client).CreateToken, req)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, resp.GetToken())

	return err
}

// permissionsFile is the YAML or JSON file "token create" reads Permissions from.
type permissionsFile struct {
	Permissions []struct {
		Verbs     []string `json:"verbs"`
		Resources []string `json:"resources"`
		Zones     []string `json:"zones"`
		Names     []string `json:"names"`
		Types     []string `json:"types"`
		Egress    []string `json:"egress"`
	} `json:"permissions"`
}

// readPermissionsFile reads the Permissions of a Derived Token from the
// YAML or JSON file path. Unknown fields are errors, and so is a Permission
// without verbs.
func readPermissionsFile(path string) ([]*dnsgatev1.Permission, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading permissions: %w", err)
	}

	var file permissionsFile
	if err := yaml.UnmarshalStrict(data, &file); err != nil {
		return nil, fmt.Errorf("permissions file %s: %w", path, err)
	}

	if len(file.Permissions) == 0 {
		return nil, fmt.Errorf("permissions file %s has no permissions", path)
	}

	perms := make([]*dnsgatev1.Permission, 0, len(file.Permissions))

	for i, p := range file.Permissions {
		if len(p.Verbs) == 0 {
			return nil, fmt.Errorf("permissions file %s: permission %d has no verbs", path, i+1)
		}

		perms = append(perms, &dnsgatev1.Permission{
			Verbs: p.Verbs, Resources: p.Resources, Zones: p.Zones, Names: p.Names, Types: p.Types, Egress: p.Egress,
		})
	}

	return perms, nil
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

	resp, err := callGateway(ctx, f, "reseal", (*client.Client).ResealToken, tok)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, resp.GetToken())

	return err
}

func newTokenRevokeCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke TOKEN_ID|TOKEN|-",
		Short: "Revoke a Service Token and every token derived from it",
		Long: "Revoke a Service Token for good: from the next request on, the Gateway refuses it and every token " +
			"derived from it. Revoking a Root Token revokes everything issued under its Onboarding. Print the " +
			"revoked token's ID.\n\n" +
			"Present a token holding delete on tokens, --" + flagToken + " or " + envToken + ". It may revoke any " +
			"token ID: the Gateway keeps no registry of which chain a token belongs to.\n\n" +
			"Name the token to revoke by its ID (tok_...), as \"token inspect\" shows it, or give the token " +
			"itself, or \"-\" to read the token from stdin; a token argument shows in process listings. Given " +
			"the token, the Gateway keeps its revoked ID only until the token expires. Given only its ID, it " +
			"cannot know the expiry and keeps the ID forever.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTokenRevoke(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), flags, args[0])
		},
	}

	flags.AddTokenFlags(cmd.Flags())
	flags.AddClientFlags(cmd.Flags())

	return cmd
}

func runTokenRevoke(ctx context.Context, in io.Reader, out io.Writer, f *Flags, target string) error {
	if target == "-" {
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("reading the token to revoke: %w", err)
		}

		if target = strings.TrimSpace(line); target == "" {
			return errors.New("no token to revoke on stdin")
		}
	}

	switch {
	case target == "":
		return errors.New("no token to revoke: give its ID or the token")
	case f.Token == "":
		return errors.New("no Service Token: set " + envToken + " or --" + flagToken)
	}

	req := &dnsgatev1.RevokeTokenRequest{Token: f.Token}
	// A malformed ID is still sent as an ID, so the Gateway's refusal
	// names it as one.
	if strings.HasPrefix(target, token.IDPrefix) {
		req.Target = &dnsgatev1.RevokeTokenRequest_TokenId{TokenId: target}
	} else {
		req.Target = &dnsgatev1.RevokeTokenRequest_TargetToken{TargetToken: target}
	}

	resp, err := callGateway(ctx, f, "token revoke", (*client.Client).RevokeToken, req)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, resp.GetJti())

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

	resp, err := callGateway(ctx, f, "inspect", (*client.Client).InspectToken, f.Token)
	if err != nil {
		return err
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
