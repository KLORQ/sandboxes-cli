package command

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type runClient struct {
	fakeClient
	sandboxes *runSandbox
	sessions  *fakeSessions
}

func (c runClient) Sandboxes() sdk.SandboxService { return c.sandboxes }
func (c runClient) SessionExecutor() sdk.SessionExecutor {
	return c.sessions
}

type runSandbox struct {
	fakeSandbox
	items       []sdk.Sandbox
	created     sdk.CreateRequest
	createCalls int
	startCalls  int
	deleteCalls int
	deleteID    string
	deleteErr   error
}

func (s *runSandbox) Create(_ context.Context, req sdk.CreateRequest) (*sdk.Operation, error) {
	s.createCalls++
	s.created = req
	item := sdk.Sandbox{ID: "sb-run", Name: req.Name, State: sdk.StateRunning, Image: req.Image, Workspace: req.Workspace}
	s.items = append(s.items, item)
	return &sdk.Operation{ID: "op-create", SandboxID: item.ID, Kind: "create", State: sdk.StateDone}, nil
}

func (s *runSandbox) Get(_ context.Context, id string) (*sdk.Sandbox, error) {
	for i := range s.items {
		if s.items[i].ID == id || s.items[i].Name == id {
			item := s.items[i]
			return &item, nil
		}
	}
	return nil, errors.New("not found")
}

func (s *runSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	items := append([]sdk.Sandbox(nil), s.items...)
	return &sdk.Page[sdk.Sandbox]{Items: items}, nil
}

func (s *runSandbox) Delete(_ context.Context, id string, _ sdk.DeleteOptions) (*sdk.Operation, error) {
	s.deleteCalls++
	s.deleteID = id
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &sdk.Operation{ID: "op-delete", State: sdk.StateDone}, nil
}

func (s *runSandbox) Start(_ context.Context, id string) (*sdk.Operation, error) {
	for i := range s.items {
		if s.items[i].ID == id {
			s.items[i].State = sdk.StateRunning
			s.startCalls++
			return &sdk.Operation{ID: "op-start", State: sdk.StateDone}, nil
		}
	}
	return nil, errors.New("not found")
}

type fakeSessions struct {
	req    sdk.SessionRequest
	opened bool
	closed bool
	input  []byte
}

func (s *fakeSessions) OpenSession(_ context.Context, req sdk.SessionRequest) (sdk.ExecSession, error) {
	s.req = req
	s.opened = true
	return &fakeSession{sessions: s}, nil
}

type fakeSession struct {
	sessions *fakeSessions
	exited   bool
}

func (s *fakeSession) SendInput(data []byte) error {
	s.sessions.input = append(s.sessions.input, data...)
	return nil
}
func (s *fakeSession) CloseInput() error {
	s.sessions.closed = true
	return nil
}
func (s *fakeSession) Resize(sdk.TerminalSize) error { return nil }
func (s *fakeSession) Receive() (sdk.SessionFrame, error) {
	if s.exited {
		return sdk.SessionFrame{}, io.EOF
	}
	s.exited = true
	code := 0
	return sdk.SessionFrame{ExitCode: &code}, nil
}

func runTestRunner(t *testing.T, client sdk.Client, input string) (*Runner, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, stderr bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &stderr, In: strings.NewReader(input), Socket: "unused",
		NewClient: func(string) (sdk.Client, error) { return client, nil },
	}
	return runner, &out, &stderr
}

func TestRunCreatesStartsAndAttachesShell(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 || sandboxes.startCalls != 0 {
		t.Fatalf("create=%d start=%d", sandboxes.createCalls, sandboxes.startCalls)
	}
	if sandboxes.created.Name != "dev" || sandboxes.created.Workspace != workspace {
		t.Fatalf("unexpected create request: %#v", sandboxes.created)
	}
	if !sessions.opened || strings.Join(sessions.req.Argv, "\x00") != "/bin/sh" || sessions.req.TTY {
		t.Fatalf("unexpected session: %#v", sessions.req)
	}
	if sessions.req.SandboxID != "sb-run" || !sessions.closed {
		t.Fatalf("session id=%q closed=%t", sessions.req.SandboxID, sessions.closed)
	}
}

func TestRunDetachPrintsSandboxIDWithoutAttaching(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "-d", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if strings.TrimSpace(out.String()) != "sb-run" || sessions.opened {
		t.Fatalf("stdout=%q opened=%t", out.String(), sessions.opened)
	}
}

func TestRunReusesAndRestartsExistingSandbox(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateStopped, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 0 || sandboxes.startCalls != 1 {
		t.Fatalf("create=%d start=%d", sandboxes.createCalls, sandboxes.startCalls)
	}
	if !sessions.opened || sessions.req.SandboxID != "sb-old" || strings.Join(sessions.req.Argv, "\x00") != "/bin/sh" {
		t.Fatalf("unexpected session: %#v", sessions.req)
	}
}

func TestRunRejectsUnimplementedAndUnknownAgents(t *testing.T) {
	for _, agent := range []string{"claude", "not-an-agent"} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
			called = true
			return runClient{}, nil
		}}
		if code := runner.Run(context.Background(), []string{"run", agent, "."}); code != 2 || called {
			t.Fatalf("agent %q: exit=%d client-called=%t", agent, code, called)
		}
	}
}

func TestRunRejectsExtraWorkspacesAndInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--name", "", "shell", "."},
		{"run", "-e", "1BAD=x", "shell", "."},
		{"run", "--rm", "--detach", "shell", "."},
	} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
			called = true
			return runClient{}, nil
		}}
		if code := runner.Run(context.Background(), args); code != 2 || called {
			t.Fatalf("%v: exit=%d client-called=%t", args, code, called)
		}
	}
}

func TestRunHelpExitsZero(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"run", "--help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "usage: ksbx run") || !strings.Contains(out.String(), "shell") {
		t.Fatalf("unexpected help: %q", out.String())
	}
}

func TestRunRejectsMissingAgentWithoutName(t *testing.T) {
	called := false
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
		called = true
		return runClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"run"}); code != 2 || called {
		t.Fatalf("exit=%d client-called=%t", code, called)
	}
}

func TestRunGeneratesUniqueNameForNewSandbox(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	want := "shell-" + sanitizeNameBase(workspace)
	if sandboxes.createCalls != 1 || sandboxes.created.Name != want {
		t.Fatalf("unexpected generated name: %q, want %q", sandboxes.created.Name, want)
	}
}

func TestRunFallsBackToHexNameWhenDerivedNameTaken(t *testing.T) {
	workspace := t.TempDir()
	taken := "shell-" + sanitizeNameBase(workspace)
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: taken, State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--new", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 {
		t.Fatalf("create=%d", sandboxes.createCalls)
	}
	name := sandboxes.created.Name
	if name == taken || !strings.HasPrefix(name, "shell-") {
		t.Fatalf("unexpected fresh name: %q", name)
	}
}

func TestRunReusesDerivedSandboxWithoutTerminal(t *testing.T) {
	workspace := t.TempDir()
	derived := "shell-" + sanitizeNameBase(workspace)
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: derived, State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "shell", workspace}); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if sandboxes.createCalls != 0 {
		t.Fatalf("create=%d, want reuse", sandboxes.createCalls)
	}
	if !sessions.opened || sessions.req.SandboxID != "sb-old" {
		t.Fatalf("session: %+v", sessions.req)
	}
}

func TestRunNewSkipsDerivedReuse(t *testing.T) {
	workspace := t.TempDir()
	derived := "shell-" + sanitizeNameBase(workspace)
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: derived, State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--new", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.createCalls != 1 || sandboxes.created.Name == derived {
		t.Fatalf("create=%d name=%q", sandboxes.createCalls, sandboxes.created.Name)
	}
}

func TestRunUnknownFlagUsesSharedErrorContract(t *testing.T) {
	runner, _, stderr := runTestRunner(t, runClient{}, "")
	if code := runner.Run(context.Background(), []string{"run", "--bogus", "shell", "."}); code != 1 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "error: unknown flag: --bogus") || !strings.Contains(stderr.String(), "  try: ksbx run --help") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunRefusesToIgnoreDifferentWorkspaceOnReuse(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: first}}}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "shell", second}); code != 1 || sessions.opened {
		t.Fatalf("exit=%d opened=%t stderr=%q", code, sessions.opened, stderr.String())
	}
	if !strings.Contains(stderr.String(), "refusing to ignore") {
		t.Fatalf("unexpected error: %q", stderr.String())
	}
}

func TestRunDetachStartsStoppedReusedSandbox(t *testing.T) {
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateStopped}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--detach", "--name", "dev"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.startCalls != 1 || sessions.opened || strings.TrimSpace(out.String()) != "sb-old" {
		t.Fatalf("start=%d opened=%t stdout=%q", sandboxes.startCalls, sessions.opened, out.String())
	}
}

func TestRunPassesEnvToSession(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "run.env")
	if err := os.WriteFile(envFile, []byte("FROM_FILE=file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "dev", "--env-file", envFile, "-e", "A=1", "--", "-c", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if want := []string{"FROM_FILE=file", "A=1"}; !reflect.DeepEqual(sessions.req.Env, want) {
		t.Fatalf("env=%q want %q", sessions.req.Env, want)
	}
}

func TestRunRemovesSandboxAfterSessionWithRM(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--rm", "--name", "dev", "--", "-c", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.deleteCalls != 1 || sandboxes.deleteID != "sb-old" {
		t.Fatalf("delete calls=%d id=%q", sandboxes.deleteCalls, sandboxes.deleteID)
	}
}

func TestRunRMReportsRemovalFailure(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}, deleteErr: errors.New("delete failed")}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--rm", "--name", "dev", "--", "-c", "true"}); code != 1 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "delete failed") || sandboxes.deleteCalls != 1 {
		t.Fatalf("unexpected failure: calls=%d stderr=%q", sandboxes.deleteCalls, stderr.String())
	}
}

func TestRunCreatesMultipleWorkspaces(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "multi", "shell", first, second + ":ro"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Workspaces) != 2 {
		t.Fatalf("workspaces=%+v", sandboxes.created.Workspaces)
	}
	if sandboxes.created.Workspaces[0].Path != first || sandboxes.created.Workspaces[0].ReadOnly {
		t.Fatalf("first workspace=%+v", sandboxes.created.Workspaces[0])
	}
	if sandboxes.created.Workspaces[1].Path != second || !sandboxes.created.Workspaces[1].ReadOnly {
		t.Fatalf("second workspace=%+v", sandboxes.created.Workspaces[1])
	}
	if sandboxes.created.Workspace != first {
		t.Fatalf("compat workspace=%q", sandboxes.created.Workspace)
	}
	if sandboxes.created.Agent != shellAgent || sandboxes.created.Detached {
		t.Fatalf("agent/detached=%q/%t", sandboxes.created.Agent, sandboxes.created.Detached)
	}
}

func TestRunBakesEnvOnCreate(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "env-run", "-e", "A=1", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.Env["A"] != "1" {
		t.Fatalf("create env=%v", sandboxes.created.Env)
	}
}
