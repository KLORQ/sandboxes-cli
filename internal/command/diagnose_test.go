package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type diagnoseSandbox struct {
	fakeSandbox
	items []sdk.Sandbox
	err   error
}

func (s diagnoseSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	if s.err != nil {
		return nil, s.err
	}
	return &sdk.Page[sdk.Sandbox]{Items: s.items}, nil
}

func TestDiagnoseReportsDaemonAndCounts(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sandboxd.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: socket, NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: diagnoseSandbox{items: []sdk.Sandbox{
			{ID: "sb-1", State: sdk.StateRunning}, {ID: "sb-2", State: sdk.StateStopped},
		}}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"diagnose", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var report diagnoseReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if !report.SocketOK || !report.DaemonOK || report.Sandboxes != 2 || report.Running != 1 || report.Stopped != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestDiagnoseReportsDaemonFailure(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: filepath.Join(t.TempDir(), "missing.sock"), NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: diagnoseSandbox{err: errors.New("dial failed")}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"diagnose"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "Socket:") || !strings.Contains(out.String(), "dial failed") || !strings.Contains(out.String(), "(missing)") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}
