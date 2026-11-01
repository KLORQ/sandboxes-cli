package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"

	"github.com/KLORQ/sandboxes-cli/internal/version"
)

const versionUsage = `usage: ksbx version [--format text|json|yaml] [--json]

Print the client version and, when the daemon is reachable, the server
version and API contract version.`

type versionClientOutput struct {
	Version  string `json:"version" yaml:"version"`
	Revision string `json:"revision,omitempty" yaml:"revision,omitempty"`
}

type versionServerOutput struct {
	State      string `json:"state" yaml:"state"`
	Version    string `json:"version,omitempty" yaml:"version,omitempty"`
	APIVersion string `json:"api_version,omitempty" yaml:"api_version,omitempty"`
	Error      string `json:"error,omitempty" yaml:"error,omitempty"`
}

type versionOutput struct {
	Client versionClientOutput `json:"client" yaml:"client"`
	Server versionServerOutput `json:"server" yaml:"server"`
}

func (r *Runner) version(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "output format: text, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, versionUsage)
			return 0
		}
		return r.flagParseFailure("version", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, versionUsage)
		return 2
	}
	selected := *format
	if *jsonOutput {
		if selected != "text" {
			_, _ = fmt.Fprintln(r.Err, "--json cannot be combined with an explicit --format")
			return 2
		}
		selected = listFormatJSON
	}
	report := versionOutput{Client: versionClientOutput{Version: "v" + version.Version, Revision: version.Commit}}
	report.Server = r.serverVersion(ctx)

	switch selected {
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			r.error(err)
			return 1
		}
		return 0
	case listFormatYAML:
		data, err := yaml.Marshal(report)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
		return 0
	case "text":
		// continue below
	default:
		_, _ = fmt.Fprintf(r.Err, "invalid format %q; use text, json or yaml\n", selected)
		return 2
	}

	if report.Client.Revision != "" {
		_, _ = fmt.Fprintf(r.Out, "ksbx version %s %s\n", report.Client.Version, report.Client.Revision)
	} else {
		_, _ = fmt.Fprintf(r.Out, "ksbx version %s\n", report.Client.Version)
	}
	if report.Server.State == "running" {
		_, _ = fmt.Fprintf(r.Out, "server %s (api %s)\n", report.Server.Version, report.Server.APIVersion)
	} else {
		_, _ = fmt.Fprintf(r.Out, "server unavailable: %s\n", report.Server.Error)
	}
	return 0
}

func (r *Runner) serverVersion(ctx context.Context) versionServerOutput {
	client, err := r.client()
	if err != nil {
		return versionServerOutput{State: stateUnavailable, Error: err.Error()}
	}
	defer func() { _ = client.Close() }()
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	info, err := sdk.Version(client).Get(checkCtx)
	if err != nil {
		return versionServerOutput{State: stateUnavailable, Error: err.Error()}
	}
	return versionServerOutput{State: "running", Version: "v" + info.Version, APIVersion: info.APIVersion}
}
