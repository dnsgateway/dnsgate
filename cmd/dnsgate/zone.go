package main

import (
	"context"
	"io"
	"strings"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/spf13/cobra"
)

func newZoneCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Read zones through the Gateway",
	}

	cmd.AddCommand(
		newZoneListCmd(flags),
		newZoneGetCmd(flags),
	)

	return cmd
}

func newZoneListCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the zones a Service Token covers",
		Long: "Print, as JSON, the zones the token's Provider Credential reaches and its Permissions cover. " +
			"The token needs list on zones.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runZoneList(cmd.Context(), cmd.OutOrStdout(), flags)
		},
	}

	flags.AddReadFlags(cmd.Flags())

	return cmd
}

func runZoneList(ctx context.Context, out io.Writer, f *Flags) error {
	egress, err := checkReadFlags(f)
	if err != nil {
		return err
	}

	resp, err := callGateway(ctx, f, "zone list", (*client.Client).ListZones,
		&dnsgatev1.ListZonesRequest{Token: f.Token, Egress: egress})
	if err != nil {
		return err
	}

	zones := make([]zoneOutput, 0, len(resp.GetZones()))
	for _, z := range resp.GetZones() {
		zones = append(zones, newZoneOutput(z))
	}

	return printJSON(out, zones)
}

func newZoneGetCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get ZONE",
		Short: "Show one zone",
		Long:  "Print, as JSON, the zone ZONE, such as example.com. The token needs get on zones for it.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runZoneGet(cmd.Context(), cmd.OutOrStdout(), flags, args[0])
		},
	}

	flags.AddReadFlags(cmd.Flags())

	return cmd
}

func runZoneGet(ctx context.Context, out io.Writer, f *Flags, zone string) error {
	egress, err := checkReadFlags(f)
	if err != nil {
		return err
	}

	resp, err := callGateway(ctx, f, "zone get", (*client.Client).GetZone,
		&dnsgatev1.GetZoneRequest{Token: f.Token, Egress: egress, Zone: zone})
	if err != nil {
		return err
	}

	return printJSON(out, newZoneOutput(resp.GetZone()))
}

// zoneOutput is a zone as "zone list" and "zone get" print it.
type zoneOutput struct {
	Name        string   `json:"name"`
	State       string   `json:"state"`
	Nameservers []string `json:"nameservers,omitempty"`
}

func newZoneOutput(z *dnsgatev1.Zone) zoneOutput {
	return zoneOutput{
		Name:        z.GetName(),
		State:       strings.ToLower(strings.TrimPrefix(z.GetState().String(), "STATE_")),
		Nameservers: z.GetNameservers(),
	}
}
