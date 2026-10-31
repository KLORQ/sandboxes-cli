package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type registrySecretOutput struct {
	Registry    string `json:"registry" yaml:"registry"`
	Username    string `json:"username" yaml:"username"`
	Scope       string `json:"scope" yaml:"scope"`
	SandboxName string `json:"sandbox_name,omitempty" yaml:"sandbox_name,omitempty"`
}

func (r *Runner) registryList(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret ls [--format table|json|yaml] [--json]")
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	lister, ok := sdk.RegistryCredentialList(client)
	if !ok {
		r.error(errors.New("registry credential listing is not supported by this client"))
		return 1
	}
	items, err := lister.ListRegistryCredentials(ctx)
	if err != nil {
		r.error(err)
		return 1
	}
	out := make([]registrySecretOutput, 0, len(items))
	for _, item := range items {
		out = append(out, registrySecretOutput{Registry: item.Registry, Username: item.Username, Scope: item.Scope, SandboxName: item.SandboxName})
	}
	if err := renderRegistrySecrets(r.Out, selected, out); err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func renderRegistrySecrets(out io.Writer, format string, items []registrySecretOutput) error {
	switch format {
	case listFormatTable:
		if len(items) == 0 {
			_, err := fmt.Fprintln(out, "No registry credentials stored")
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "REGISTRY\tUSERNAME\tSCOPE\tSANDBOX")
		for _, item := range items {
			sandbox := item.SandboxName
			if sandbox == "" {
				sandbox = "-"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", item.Registry, item.Username, item.Scope, sandbox)
		}
		return tw.Flush()
	case listFormatYAML:
		data, err := yaml.Marshal(items)
		if err != nil {
			return err
		}
		_, err = out.Write(data)
		return err
	default:
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(items)
	}
}
