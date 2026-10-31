package command

import (
	"bytes"
	"context"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestResolveWorkspacesReadsReadOnlyAndRejectsDuplicates(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	workspaces, err := resolveWorkspaces([]string{first, second + ":ro"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(workspaces) != 2 || workspaces[0].ReadOnly || !workspaces[1].ReadOnly || workspaces[1].Path != second {
		t.Fatalf("workspaces=%+v", workspaces)
	}
	if _, err := resolveWorkspaces([]string{first, first}, true); err == nil {
		t.Fatal("duplicate workspace accepted")
	}
	if _, err := resolveWorkspaces([]string{first, "/does/not/exist"}, true); err == nil {
		t.Fatal("missing workspace accepted")
	}
	if _, err := resolveWorkspaces(nil, false); err != nil {
		t.Fatalf("empty mountless workspaces: %v", err)
	}
}

func TestCreatePassesMultipleWorkspaces(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--workspace", first, "--workspace", second + ":ro", "multi"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.request.Workspaces) != 2 || sandbox.request.Workspaces[0].ReadOnly || !sandbox.request.Workspaces[1].ReadOnly {
		t.Fatalf("request=%+v", sandbox.request)
	}
	if sandbox.request.Workspace != first {
		t.Fatalf("compat workspace=%q", sandbox.request.Workspace)
	}
}

func TestCreateRejectsMissingWorkspace(t *testing.T) {
	called := false
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
		called = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"create", "--workspace", "/definitely/not/here", "dev"}); code != 2 || called {
		t.Fatalf("exit=%d client-called=%t", code, called)
	}
	if !strings.Contains(runner.Err.(*bytes.Buffer).String(), "workspace") {
		t.Fatalf("missing error: %q", runner.Err)
	}
}
