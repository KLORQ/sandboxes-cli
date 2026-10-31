package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

// TestLsUnknownFlagUsesSharedErrorContract covers PARITY P-34.
func TestLsUnknownFlagUsesSharedErrorContract(t *testing.T) {
	var out, stderr bytes.Buffer
	runner := &Runner{Out: &out, Err: &stderr, NewClient: func(string) (sdk.Client, error) {
		return runClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"ls", "--bogus"}); code != 1 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "error: unknown flag: --bogus") ||
		!strings.Contains(stderr.String(), "  try: ksbx ls --help") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

// TestStopAndRmHumanOutput covers PARITY P-23.
func TestStopAndRmHumanOutput(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}}
	runner, out, _ := runTestRunner(t, runClient{sandboxes: sandboxes}, "")
	if code := runner.Run(context.Background(), []string{"stop", "dev"}); code != 0 {
		t.Fatalf("stop exit=%d", code)
	}
	if !strings.Contains(out.String(), "Stopped sandbox dev") {
		t.Fatalf("stop output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"rm", "-f", "dev"}); code != 0 {
		t.Fatalf("rm exit=%d", code)
	}
	if !strings.Contains(out.String(), "Removed sandbox dev") {
		t.Fatalf("rm output=%q", out.String())
	}
}

// TestStopJSONKeepsOperationRecords pins the machine contract for P-23.
func TestStopJSONKeepsOperationRecords(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: sdk.StateRunning}}}
	runner, out, _ := runTestRunner(t, runClient{sandboxes: sandboxes}, "")
	if code := runner.Run(context.Background(), []string{"stop", "--format", "json", "dev"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	var ops []operationOutput
	if err := json.Unmarshal(out.Bytes(), &ops); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if len(ops) != 1 || ops[0].Kind == "" {
		t.Fatalf("ops=%+v", ops)
	}
}

// TestPruneDryRunNarrative covers PARITY P-36.
func TestPruneDryRunNarrative(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "old", State: sdk.StateStopped, Agent: "shell", Workspace: "/work/old"},
		{ID: "sb-2", Name: "live", State: sdk.StateRunning},
	}}
	runner, out, _ := runTestRunner(t, runClient{sandboxes: sandboxes}, "")
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	text := out.String()
	if !strings.Contains(text, "Would remove 1 stopped sandboxes:") ||
		!strings.Contains(text, "SANDBOX") || !strings.Contains(text, "AGENT") ||
		!strings.Contains(text, "STOPPED") || !strings.Contains(text, "WORKSPACE") ||
		!strings.Contains(text, "old") || strings.Contains(text, "live") {
		t.Fatalf("output=%q", text)
	}
}

// TestPruneRemovesWithNarrative covers the non-dry-run table rendering.
func TestPruneRemovesWithNarrative(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "old", State: sdk.StateStopped, Agent: "shell"},
	}}
	runner, out, _ := runTestRunner(t, runClient{sandboxes: sandboxes}, "")
	if code := runner.Run(context.Background(), []string{"prune", "--force"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "Removed 1 stopped sandboxes:") {
		t.Fatalf("output=%q", out.String())
	}
}

// TestRunTemplateAndPublishAliases covers PARITY P-13.
func TestRunTemplateAndPublishAliases(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	code := runner.Run(context.Background(), []string{"run", "-d", "-t", "alpine:3.22", "-p", "8080:80", "shell", workspace})
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.Image != "alpine:3.22" {
		t.Fatalf("image=%q", sandboxes.created.Image)
	}
	if len(sandboxes.created.Ports) != 1 || sandboxes.created.Ports[0].Host != 8080 || sandboxes.created.Ports[0].Guest != 80 {
		t.Fatalf("ports=%+v", sandboxes.created.Ports)
	}
}

// TestCreateTemplateAlias covers PARITY P-13 for create.
func TestCreateTemplateAlias(t *testing.T) {
	sandboxes := &runSandbox{}
	runner, out, _ := runTestRunner(t, runClient{sandboxes: sandboxes}, "")
	if code := runner.Run(context.Background(), []string{"create", "-t", "alpine:3.22", "--name", "tmpl", "shell"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandboxes.created.Image != "alpine:3.22" {
		t.Fatalf("image=%q", sandboxes.created.Image)
	}
}

func TestCreateRejectsTemplateAndImageTogether(t *testing.T) {
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: &runSandbox{}}, "")
	if code := runner.Run(context.Background(), []string{"create", "-t", "a", "--image", "b", "shell"}); code != 2 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "cannot be combined") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

// TestPolicyCheckNetworkGrammar covers PARITY P-20.
func TestPolicyCheckNetworkGrammar(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{
		ID: "sb-1", Name: "dev", State: sdk.StateRunning,
		Allow: []sdk.NetworkRule{{Protocol: "tcp", CIDR: "192.0.2.0/24", Port: 443}},
	}}}
	cases := []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"policy", "check", "network", "--sandbox", "dev", "192.0.2.1:443"}, 0, "allowed: allow rule 192.0.2.0/24"},
		{[]string{"policy", "check", "network", "--sandbox", "dev", "192.0.2.1"}, 0, "allowed: allow rule 192.0.2.0/24"},
		{[]string{"policy", "check", "network", "--sandbox", "dev", "198.51.100.9:443"}, 1, "denied: default deny"},
		{[]string{"policy", "check", "network", "198.51.100.1"}, 1, "denied: default deny"},
		{[]string{"policy", "allow", "network", "192.0.2.0/24"}, 1, "global policy rules are not implemented"},
		{[]string{"policy", "check", "network", "https://192.0.2.1/x"}, 1, "denied: default deny"},
	}
	for _, tc := range cases {
		runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes}, "")
		if code := runner.Run(context.Background(), tc.args); code != tc.code {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", tc.args, code, out.String(), stderr.String())
		}
		if !strings.Contains(out.String()+stderr.String(), tc.contains) {
			t.Fatalf("%v: output %q/%q missing %q", tc.args, out.String(), stderr.String(), tc.contains)
		}
	}
}

func TestParsePolicyTarget(t *testing.T) {
	cases := []struct {
		target  string
		host    string
		port    uint16
		wantErr bool
	}{
		{"192.0.2.1", "192.0.2.1", 0, false},
		{"192.0.2.1:443", "192.0.2.1", 443, false},
		{"https://192.0.2.1/path", "192.0.2.1", 443, false},
		{"http://192.0.2.1:8080", "192.0.2.1", 8080, false},
		{"192.0.2.1:0", "", 0, true},
		{"example.com", "", 0, false}, // nil host; the caller rejects non-IP targets
	}
	for _, tc := range cases {
		host, port, err := parsePolicyTarget(tc.target)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error", tc.target)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.target, err)
		}
		if host == nil {
			if tc.host != "" {
				t.Fatalf("%s: nil host, want %q", tc.target, tc.host)
			}
			continue
		}
		if host.String() != tc.host || port != tc.port {
			t.Fatalf("%s: host=%v port=%d", tc.target, host, port)
		}
	}
}

// TestVersionCommandJSON covers PARITY P-31.
func TestVersionCommandJSON(t *testing.T) {
	client := versionFakeClient{info: sdk.VersionInfo{Version: "0.0.9", APIVersion: "0.0.5"}}
	runner, out, _ := runTestRunner(t, client, "")
	if code := runner.Run(context.Background(), []string{"version", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	var report versionOutput
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if report.Client.Version == "" || report.Server.State != "running" || report.Server.APIVersion != "0.0.5" {
		t.Fatalf("report=%+v", report)
	}
}

func TestVersionCommandUnavailableServer(t *testing.T) {
	client := versionFakeClient{err: errors.New("dial failed")}
	runner, out, _ := runTestRunner(t, client, "")
	if code := runner.Run(context.Background(), []string{"version", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	var report versionOutput
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("json %q: %v", out.String(), err)
	}
	if report.Server.State != "unavailable" || report.Server.Error == "" {
		t.Fatalf("report=%+v", report)
	}
}

func TestVersionCommandText(t *testing.T) {
	runner, out, _ := runTestRunner(t, versionFakeClient{err: errors.New("dial failed")}, "")
	if code := runner.Run(context.Background(), []string{"version"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "ksbx version v0.0.9") {
		t.Fatalf("output=%q", out.String())
	}
}

type versionFakeClient struct {
	runClient
	info sdk.VersionInfo
	err  error
}

func (v versionFakeClient) VersionService() sdk.VersionService { return versionFakeService{v} }

type versionFakeService struct{ client versionFakeClient }

func (s versionFakeService) Get(context.Context) (sdk.VersionInfo, error) {
	return s.client.info, s.client.err
}

// TestFileClosesOnEOF pins the non-terminal stdin model for PARITY P-11.
func TestFileClosesOnEOF(t *testing.T) {
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	if fileClosesOnEOF(null) {
		t.Fatal("/dev/null must keep the session attached")
	}
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = pipeWriter.Close()
	defer func() { _ = pipeReader.Close() }()
	if !fileClosesOnEOF(pipeReader) {
		t.Fatal("a pipe must close the session input at EOF")
	}
	regular, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = regular.Close() }()
	if !fileClosesOnEOF(regular) {
		t.Fatal("a regular file must close the session input at EOF")
	}
}

// TestExplainCopyError covers PARITY P-35 workspace-specific escape messages.
func TestExplainCopyError(t *testing.T) {
	workspaces := []sdk.Workspace{{Path: "/work"}}
	plain := errors.New("some failure")
	if got := explainCopyError(plain, workspaces); !errors.Is(got, plain) {
		t.Fatalf("plain error was wrapped: %v", got)
	}
	escape := errors.New("openat /etc/passwd: path escapes from parent")
	got := explainCopyError(escape, workspaces)
	if !strings.Contains(got.Error(), "path escapes from parent") ||
		!strings.Contains(got.Error(), "/work") ||
		!strings.Contains(got.Error(), "mounted workspace") {
		t.Fatalf("escape error = %v", got)
	}
	if noCtx := explainCopyError(escape, nil); !errors.Is(noCtx, escape) {
		t.Fatalf("error without workspaces was wrapped: %v", noCtx)
	}
}

// TestWorkspaceNameBase covers PARITY P-14 name derivation.
func TestWorkspaceNameBase(t *testing.T) {
	cases := map[string]string{
		"/Users/x/My Proj":    "my-proj",
		"/a/b/c":              "c",
		"/tmp/..":             "",
		"/weird/UPPER_case.1": "upper_case.1",
	}
	for path, want := range cases {
		if got := sanitizeNameBase(path); got != want {
			t.Fatalf("sanitizeNameBase(%q)=%q want %q", path, got, want)
		}
	}
	if got := workspaceNameBase(nil); got != "" {
		t.Fatalf("empty paths = %q", got)
	}
}
