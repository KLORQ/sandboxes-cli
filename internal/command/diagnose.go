package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	sdk "github.com/KLORQ/sandboxes-go-sdk"

	"github.com/KLORQ/sandboxes-cli/internal/version"
)

type diagnoseReport struct {
	Socket     string `json:"socket" yaml:"socket"`
	SocketOK   bool   `json:"socket_ok" yaml:"socket_ok"`
	Binary     string `json:"binary" yaml:"binary"`
	Version    string `json:"version" yaml:"version"`
	DaemonOK   bool   `json:"daemon_ok" yaml:"daemon_ok"`
	Server     string `json:"server,omitempty" yaml:"server,omitempty"`
	APIVersion string `json:"api_version,omitempty" yaml:"api_version,omitempty"`
	Sandboxes  int    `json:"sandboxes" yaml:"sandboxes"`
	Running    int    `json:"running" yaml:"running"`
	Stopped    int    `json:"stopped" yaml:"stopped"`
	Error      string `json:"error,omitempty" yaml:"error,omitempty"`
}

const diagnoseUsage = "usage: ksbx diagnose [--format table|json|yaml] [--json]"

func (r *Runner) diagnose(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprintln(r.Out, diagnoseUsage)
			return 0
		}
		return r.flagParseFailure("diagnose", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, diagnoseUsage)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	report := diagnoseReport{Socket: r.Socket, Version: "v" + version.Version}
	if binary, err := os.Executable(); err == nil {
		report.Binary = binary
	}
	if _, err := os.Stat(r.Socket); err == nil {
		report.SocketOK = true
	}
	failure := r.collectDiagnose(ctx, &report)
	report.Error = ""
	if failure != nil {
		report.Error = failure.Error()
	}

	switch selected {
	case listFormatJSON:
		encoder := json.NewEncoder(r.Out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			r.error(err)
			return 1
		}
	case listFormatYAML:
		data, err := yaml.Marshal(report)
		if err != nil {
			r.error(err)
			return 1
		}
		_, _ = r.Out.Write(data)
	default:
		r.writeDiagnoseText(report)
	}
	if failure != nil {
		return 1
	}
	return 0
}

func (r *Runner) collectDiagnose(ctx context.Context, report *diagnoseReport) error {
	client, err := r.client()
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := sdk.Version(client).Get(checkCtx)
	if err == nil {
		report.Server = "v" + info.Version
		report.APIVersion = info.APIVersion
	}
	page, err := client.Sandboxes().List(checkCtx, sdk.ListOptions{PageSize: 200})
	if err != nil {
		return err
	}
	report.DaemonOK = true
	report.Sandboxes = len(page.Items)
	for i := range page.Items {
		switch page.Items[i].State {
		case sdk.StateRunning:
			report.Running++
		case sdk.StateStopped:
			report.Stopped++
		}
	}
	return nil
}

func (r *Runner) writeDiagnoseText(report diagnoseReport) {
	binaryState := "not found"
	if report.Binary != "" {
		binaryState = report.Binary
	}
	_, _ = fmt.Fprintf(r.Out, "INSTALLATION\n  CLI binary: %s\n  Version: %s\n\n", binaryState, report.Version)
	socketState := "missing"
	if report.SocketOK {
		socketState = "present"
	}
	_, _ = fmt.Fprintf(r.Out, "CONNECTION\n  Socket: %s (%s)\n", report.Socket, socketState)
	if !report.DaemonOK {
		if report.Error != "" {
			_, _ = fmt.Fprintf(r.Out, "  Daemon: error: %s\n", report.Error)
		} else {
			_, _ = fmt.Fprintln(r.Out, "  Daemon: unreachable")
		}
		return
	}
	if report.Server != "" {
		_, _ = fmt.Fprintf(r.Out, "  Daemon: ok (%s, api %s)\n", report.Server, report.APIVersion)
	} else {
		_, _ = fmt.Fprintln(r.Out, "  Daemon: ok")
	}
	_, _ = fmt.Fprintf(r.Out, "\nSANDBOXES\n  %d sandboxes (%d running, %d stopped)\n", report.Sandboxes, report.Running, report.Stopped)
	_, _ = fmt.Fprintln(r.Out, "\nPOLICY\n  Default network policy: deny (no global rules)")
}
