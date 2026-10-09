package main

import (
	"context"
	"errors"
	"io"

	"github.com/spf13/cobra"

	dnsgatev1 "github.com/dnsgateway/dnsgate/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate/internal/client"
)

// namesHelp explains record names in the help of record commands.
const namesHelp = "Record names are relative to the zone: www.apps for www.apps.example.com, @ for the zone itself."

func newRecordCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "Read DNS records through the Gateway",
	}

	cmd.AddCommand(
		newRecordListCmd(flags),
		newRecordGetCmd(flags),
	)

	return cmd
}

func newRecordListCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the RRsets of a zone a Service Token covers",
		Long: "Print, as JSON, the RRsets of --" + flagZone + " that the token's Permissions cover. " +
			"The token needs list on records in the zone. " + namesHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRecordList(cmd.Context(), cmd.OutOrStdout(), flags)
		},
	}

	flags.AddZoneFlag(cmd.Flags())
	flags.AddTokenFlags(cmd.Flags())
	flags.AddEgressFlag(cmd.Flags())
	flags.AddClientFlags(cmd.Flags())

	return cmd
}

func runRecordList(ctx context.Context, out io.Writer, f *Flags) error {
	egress, err := checkRecordFlags(f)
	if err != nil {
		return err
	}

	resp, err := callGateway(ctx, f, "record list", (*client.Client).ListRecords,
		&dnsgatev1.ListRecordsRequest{Token: f.Token, Egress: egress, Zone: f.Zone})
	if err != nil {
		return err
	}

	sets := make([]recordSetOutput, 0, len(resp.GetRecordSets()))
	for _, s := range resp.GetRecordSets() {
		sets = append(sets, newRecordSetOutput(s))
	}

	return printJSON(out, sets)
}

func newRecordGetCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get NAME TYPE",
		Short: "Show one RRset",
		Long: "Print, as JSON, the RRset of NAME and TYPE in --" + flagZone + ": every record of that name and type. " +
			"The token needs get on records for the zone, name and type. " + namesHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordGet(cmd.Context(), cmd.OutOrStdout(), flags, args[0], args[1])
		},
	}

	flags.AddZoneFlag(cmd.Flags())
	flags.AddTokenFlags(cmd.Flags())
	flags.AddEgressFlag(cmd.Flags())
	flags.AddClientFlags(cmd.Flags())

	return cmd
}

func runRecordGet(ctx context.Context, out io.Writer, f *Flags, name, typ string) error {
	egress, err := checkRecordFlags(f)
	if err != nil {
		return err
	}

	resp, err := callGateway(ctx, f, "record get", (*client.Client).GetRecord,
		&dnsgatev1.GetRecordRequest{Token: f.Token, Egress: egress, Zone: f.Zone, Name: name, Type: typ})
	if err != nil {
		return err
	}

	return printJSON(out, newRecordSetOutput(resp.GetRecordSet()))
}

// checkRecordFlags checks the flags of the record commands and returns
// the Egress asked for.
func checkRecordFlags(f *Flags) (dnsgatev1.Egress, error) {
	if f.Zone == "" {
		return 0, errors.New("no zone: set " + envZone + " or --" + flagZone)
	}

	return checkReadFlags(f)
}

// recordSetOutput is an RRset as "record list" and "record get" print it.
type recordSetOutput struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	TTL    uint32   `json:"ttl"`
	Values []string `json:"values"`
}

func newRecordSetOutput(s *dnsgatev1.RecordSet) recordSetOutput {
	return recordSetOutput{Name: s.GetName(), Type: s.GetType(), TTL: s.GetTtl(), Values: s.GetValues()}
}
