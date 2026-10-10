package main

import (
	"context"
	"io"

	dnsgatev1 "github.com/dnsgateway/dnsgate-go/api/dnsgate/v1"
	"github.com/dnsgateway/dnsgate-go/client"
	"github.com/spf13/cobra"
)

// namesHelp explains record names in the help of record commands.
const namesHelp = "Record names are relative to the zone: www.apps for www.apps.example.com, @ for the zone itself."

// valuesHelp explains record values in the help of record commands that
// change them.
const valuesHelp = `Values are in zone-file presentation form, such as 192.0.2.1, "10 mail.example.com" for MX, or "v=spf1 -all" for TXT, with no quotes inside the value.`

// extrasHelp explains --extra in the help of record commands that change
// values.
const extrasHelp = "Each --" + flagExtra + " KEY=VALUE sets a Record Extra, a Provider-specific setting such as Cloudflare's proxied, " +
	"on every value given; KEY= clears it. A value the RRset holds keeps the Record Extras not given; a new one starts with those given, " +
	"plus those the Provider keeps of a record the Gateway reuses for it. " +
	"The Gateway refuses a Record Extra the Provider does not take on write, given for a new value or changed on a held one."

func newRecordCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "record",
		Short: "Read and change DNS records through the Gateway",
	}

	cmd.AddCommand(
		newRecordListCmd(flags),
		newRecordGetCmd(flags),
		newRecordCreateCmd(flags),
		newRecordUpdateCmd(flags),
		newRecordPatchCmd(flags),
		newRecordDeleteCmd(flags),
	)

	return cmd
}

func newRecordListCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the RRsets of a zone a Service Token covers",
		Long: "Print, as JSON, the RRsets of --" + flagZone + " that the token's Permissions cover. " +
			"The token needs list on records in the zone. When its Permissions do not cover every name and type in the zone, " +
			"a note on stderr says the list is a partial view. " + namesHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRecordList(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), flags)
		},
	}

	flags.AddRecordFlags(cmd.Flags())

	return cmd
}

func runRecordList(ctx context.Context, out, errOut io.Writer, f *Flags) error {
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

	return printList(out, errOut, sets, resp.GetPartial(), "every name and type in "+f.Zone)
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

	flags.AddRecordFlags(cmd.Flags())

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

func newRecordCreateCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create NAME TYPE VALUE...",
		Short: "Create an RRset",
		Long: "Create the RRset of NAME and TYPE in --" + flagZone + ", one record per VALUE, and print it as JSON. " +
			"The zone must not hold the RRset yet. The token needs create on records for the zone, name and type. " +
			valuesHelp + " " + extrasHelp + " " + namesHelp,
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordCreate(cmd.Context(), cmd.OutOrStdout(), flags, args[0], args[1], args[2:])
		},
	}

	flags.AddRecordWriteFlags(cmd.Flags())

	return cmd
}

func runRecordCreate(ctx context.Context, out io.Writer, f *Flags, name, typ string, values []string) error {
	egress, records, err := checkRecordWriteFlags(f, values)
	if err != nil {
		return err
	}

	return runRecordWrite(ctx, out, f, "record create", (*client.Client).CreateRecord,
		&dnsgatev1.CreateRecordRequest{Token: f.Token, Egress: egress, Zone: f.Zone, Name: name, Type: typ, Ttl: f.TTL, Records: records})
}

func newRecordUpdateCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update NAME TYPE VALUE...",
		Short: "Replace an RRset",
		Long: "Replace every record of NAME and TYPE in --" + flagZone + " with one record per VALUE, and print the RRset as JSON. " +
			"The zone must hold the RRset. The token needs update on records for the zone, name and type. " +
			valuesHelp + " " + extrasHelp + " " + namesHelp,
		Args: cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordUpdate(cmd.Context(), cmd.OutOrStdout(), flags, args[0], args[1], args[2:])
		},
	}

	flags.AddRecordWriteFlags(cmd.Flags())

	return cmd
}

func runRecordUpdate(ctx context.Context, out io.Writer, f *Flags, name, typ string, values []string) error {
	egress, records, err := checkRecordWriteFlags(f, values)
	if err != nil {
		return err
	}

	return runRecordWrite(ctx, out, f, "record update", (*client.Client).UpdateRecord,
		&dnsgatev1.UpdateRecordRequest{Token: f.Token, Egress: egress, Zone: f.Zone, Name: name, Type: typ, Ttl: f.TTL, Records: records})
}

// runRecordWrite runs "record create" or "record update", cmd: it sends
// req with op and prints the RRset the Gateway answers with.
func runRecordWrite[A any, R interface{ GetRecordSet() *dnsgatev1.RecordSet }](
	ctx context.Context, out io.Writer, f *Flags, cmd string, op func(*client.Client, context.Context, A) (R, error), req A,
) error {
	resp, err := callGateway(ctx, f, cmd, op, req)
	if err != nil {
		return err
	}

	return printJSON(out, newRecordSetOutput(resp.GetRecordSet()))
}

func newRecordPatchCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "patch NAME TYPE",
		Short: "Add values to an RRset and remove others",
		Long: "Add each --" + flagAdd + " value to the RRset of NAME and TYPE in --" + flagZone + " and remove each --" + flagRemove +
			" value from it, leaving its other records as they are, and print the RRset as JSON, or nothing once it holds no value. " +
			"Adding a value it holds changes only its Record Extras, as --" + flagExtra + " sets them, and removing one it does not hold changes nothing; " +
			"adding to an RRset the zone lacks creates it, " +
			"and removing its last value deletes it. The token needs patch on records for the zone, name and type, and nothing more: " +
			"a token that holds only patch can thereby create and empty RRsets. " + valuesHelp + " " + extrasHelp + " " + namesHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordPatch(cmd.Context(), cmd.OutOrStdout(), flags, args[0], args[1])
		},
	}

	flags.AddRecordPatchFlags(cmd.Flags())

	return cmd
}

func runRecordPatch(ctx context.Context, out io.Writer, f *Flags, name, typ string) error {
	egress, err := checkRecordFlags(f)
	if err != nil {
		return err
	}

	add, err := f.recordValues(f.Add)
	if err != nil {
		return err
	}

	resp, err := callGateway(ctx, f, "record patch", (*client.Client).PatchRecord, &dnsgatev1.PatchRecordRequest{
		Token: f.Token, Egress: egress, Zone: f.Zone, Name: name, Type: typ, Ttl: f.TTL, Add: add, Remove: f.Remove,
	})
	if err != nil {
		return err
	}

	if resp.GetRecordSet() == nil {
		return nil
	}

	return printJSON(out, newRecordSetOutput(resp.GetRecordSet()))
}

func newRecordDeleteCmd(flags *Flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete NAME TYPE",
		Short: "Delete an RRset",
		Long: "Delete every record of NAME and TYPE in --" + flagZone + ". The zone must hold the RRset. " +
			"The token needs delete on records for the zone, name and type. " + namesHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecordDelete(cmd.Context(), flags, args[0], args[1])
		},
	}

	flags.AddRecordFlags(cmd.Flags())

	return cmd
}

func runRecordDelete(ctx context.Context, f *Flags, name, typ string) error {
	egress, err := checkRecordFlags(f)
	if err != nil {
		return err
	}

	_, err = callGateway(ctx, f, "record delete", (*client.Client).DeleteRecord,
		&dnsgatev1.DeleteRecordRequest{Token: f.Token, Egress: egress, Zone: f.Zone, Name: name, Type: typ})

	return err
}

// recordSetOutput is an RRset as the record commands print it.
type recordSetOutput struct {
	Name    string              `json:"name"`
	Type    string              `json:"type"`
	TTL     uint32              `json:"ttl"`
	Records []recordValueOutput `json:"records"`
}

// recordValueOutput is one value of an RRset with its Record Extras.
type recordValueOutput struct {
	Value  string            `json:"value"`
	Extras map[string]string `json:"extras,omitempty"`
}

func newRecordSetOutput(s *dnsgatev1.RecordSet) recordSetOutput {
	records := make([]recordValueOutput, 0, len(s.GetRecords()))
	for _, r := range s.GetRecords() {
		records = append(records, recordValueOutput{Value: r.GetValue(), Extras: r.GetExtras()})
	}

	return recordSetOutput{Name: s.GetName(), Type: s.GetType(), TTL: s.GetTtl(), Records: records}
}
