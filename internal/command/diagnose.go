package command

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type diagnoseReport struct {
	Socket    string `json:"socket" yaml:"socket"`
	SocketOK  bool   `json:"socket_ok" yaml:"socket_ok"`
	DaemonOK  bool   `json:"daemon_ok" yaml:"daemon_ok"`
	Sandboxes int    `json:"sandboxes" yaml:"sandboxes"`
	Running   int    `json:"running" yaml:"running"`
	Stopped   int    `json:"stopped" yaml:"stopped"`
	Error     string `json:"error,omitempty" yaml:"error,omitempty"`
}

func (r *Runner) diagnose(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx diagnose [--json]")
		return 2
	}
	report := diagnoseReport{Socket: r.Socket}
	if _, err := os.Stat(r.Socket); err == nil {
		report.SocketOK = true
	}
	client, err := r.client()
	if err != nil {
		return r.finishDiagnose(report, err, *jsonOutput)
	}
	defer func() { _ = client.Close() }()
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	page, err := client.Sandboxes().List(checkCtx, sdk.ListOptions{PageSize: 200})
	if err != nil {
		return r.finishDiagnose(report, err, *jsonOutput)
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
	return r.finishDiagnose(report, nil, *jsonOutput)
}

func (r *Runner) finishDiagnose(report diagnoseReport, failure error, asJSON bool) int {
	if failure != nil {
		report.Error = failure.Error()
	}
	if asJSON {
		if err := r.writeDiagnoseJSON(report); err != nil {
			r.error(err)
			return 1
		}
	} else {
		r.writeDiagnoseText(report, failure)
	}
	if failure != nil {
		return 1
	}
	return 0
}

func (r *Runner) writeDiagnoseJSON(report diagnoseReport) error {
	encoder := json.NewEncoder(r.Out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (r *Runner) writeDiagnoseText(report diagnoseReport, failure error) {
	socketState := "missing"
	if report.SocketOK {
		socketState = "present"
	}
	_, _ = fmt.Fprintf(r.Out, "socket: %s (%s)\n", report.Socket, socketState)
	if failure != nil {
		_, _ = fmt.Fprintf(r.Out, "daemon: error: %s\n", failure)
		return
	}
	_, _ = fmt.Fprintf(r.Out, "daemon: ok\nsandboxes: %d (running %d, stopped %d)\n", report.Sandboxes, report.Running, report.Stopped)
}
