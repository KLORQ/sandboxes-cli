package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestParseMemoryMiB(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  uint32
		ok    bool
	}{
		{"", 0, true},
		{"512m", 512, true},
		{"512M", 512, true},
		{"2g", 2048, true},
		{"1GiB", 1024, true},
		{"1gib", 1024, true},
		{"128m", 128, true},
		{"64m", 0, false},
		{"0", 0, false},
		{"1.5g", 0, false},
		{"unknown", 0, false},
		{"65537m", 0, false},
	} {
		got, err := parseMemoryMiB(tc.value)
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("parseMemoryMiB(%q)=%d,%v", tc.value, got, err)
		}
	}
}

type recordingCreateSandbox struct {
	fakeSandbox
	request sdk.CreateRequest
}

func (s *recordingCreateSandbox) Create(_ context.Context, req sdk.CreateRequest) (*sdk.Operation, error) {
	s.request = req
	return &sdk.Operation{ID: "op-create", SandboxID: "sb-1", State: sdk.StateDone}, nil
}

func TestCreatePassesResources(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--cpus", "3", "--memory", "2g", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.CPUs != 3 || sandbox.request.MemoryMiB != 2048 {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestCreateRejectsInvalidResources(t *testing.T) {
	for _, args := range [][]string{
		{"create", "--cpus", "65", "dev"},
		{"create", "--memory", "64m", "dev"},
		{"create", "--memory", "bogus", "dev"},
	} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
			called = true
			return fakeClient{}, nil
		}}
		if code := runner.Run(context.Background(), args); code != 2 || called {
			t.Fatalf("%v: exit=%d client-called=%t", args, code, called)
		}
	}
}

func TestRunPassesResourcesOnCreate(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--cpus", "3", "--memory", "2g", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.CPUs != 3 || sandboxes.created.MemoryMiB != 2048 || sandboxes.created.Name != "dev" {
		t.Fatalf("create request=%+v", sandboxes.created)
	}
}

func TestRunWarnsThatSizingDoesNotResizeExistingSandbox(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{items: []sdk.Sandbox{{ID: "sb-old", Name: "dev", State: sdk.StateRunning, Workspace: workspace}}}
	sessions := &fakeSessions{}
	runner, _, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--cpus", "3", "--name", "dev"}); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "keeps its existing CPU/memory") || sandboxes.createCalls != 0 {
		t.Fatalf("stderr=%q createCalls=%d", stderr.String(), sandboxes.createCalls)
	}
}
