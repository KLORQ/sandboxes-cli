package command

import (
	"bytes"
	"context"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestCreateAcceptsAgentAndPositionalWorkspaces(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "shell", first, second + ":ro"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Agent != shellAgent || len(sandbox.request.Workspaces) != 2 ||
		!sandbox.request.Workspaces[1].ReadOnly || sandbox.request.Name == "" {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestCreateNameFlagWithAgent(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--name", "dev", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Name != "dev" || sandbox.request.Agent != shellAgent {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestCreateRejectsUnsupportedAgentBeforeConnecting(t *testing.T) {
	called := false
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
		called = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"create", "claude", "."}); code != 2 || called {
		t.Fatalf("exit=%d client-called=%t", code, called)
	}
}
