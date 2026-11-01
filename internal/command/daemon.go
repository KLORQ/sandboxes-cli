package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const daemonUsage = `Usage: ksbx daemon COMMAND

Commands:
  status [--json]   show socket, version and sandbox counts

start, stop, restart and log-level are not implemented: this build does not
install or supervise a host service. Run klorqd/sandboxesd from your process
manager instead.
`

func (r *Runner) daemon(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(r.Err, daemonUsage)
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprint(r.Out, daemonUsage)
		return 0
	case "status":
		return r.daemonStatus(args[1:])
	case "start", "stop", "restart", "log-level":
		_, _ = fmt.Fprintf(r.Err, "ksbx daemon %s: not implemented; this build does not install or supervise a host service\n", args[0])
		return 1
	default:
		_, _ = fmt.Fprintf(r.Err, "ksbx daemon: unknown subcommand %q\n", args[0])
		return 2
	}
}

type daemonStatusOutput struct {
	Socket  string `json:"socket"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	API     string `json:"api_version,omitempty"`
	Total   int    `json:"sandboxes"`
	Running int    `json:"running"`
	Stopped int    `json:"stopped"`
	Error   string `json:"error,omitempty"`
}

//nolint:gocognit,nestif // one status report combines version and counts.
func (r *Runner) daemonStatus(args []string) int {
	fs := flag.NewFlagSet("daemon status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return r.flagParseFailure("daemon status", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx daemon status [--json]")
		return 2
	}
	out := daemonStatusOutput{Socket: r.Socket, State: stateUnavailable}
	client, err := r.client()
	if err == nil {
		defer func() { _ = client.Close() }()
		info, versionErr := sdk.Version(client).Get(context.Background())
		if versionErr != nil {
			out.Error = versionErr.Error()
		} else {
			out.State = "ok"
			out.Version = "v" + info.Version
			out.API = info.APIVersion
			if items, listErr := collectSandboxes(context.Background(), client, 1000); listErr == nil {
				out.Total = len(items)
				for i := range items {
					switch items[i].State {
					case sdk.StateRunning:
						out.Running++
					case sdk.StateStopped:
						out.Stopped++
					}
				}
			}
		}
	} else {
		out.Error = err.Error()
	}
	if *jsonOutput {
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(out); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	_, _ = fmt.Fprintf(r.Out, "socket: %s\nstate: %s\n", out.Socket, out.State)
	if out.State == "ok" {
		_, _ = fmt.Fprintf(r.Out, "version: %s (api %s)\nsandboxes: %d (running %d, stopped %d)\n", out.Version, out.API, out.Total, out.Running, out.Stopped)
		return 0
	}
	if out.Error != "" {
		_, _ = fmt.Fprintf(r.Out, "error: %s\n", out.Error)
	}
	return 1
}
