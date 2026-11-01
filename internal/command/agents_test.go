package command

import (
	"bytes"
	"context"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestKimiAgentSpec(t *testing.T) {
	if agentImage("kimi") == "" || agentCommand("kimi") != "kimi" {
		t.Fatalf("image=%q command=%q", agentImage("kimi"), agentCommand("kimi"))
	}
	if err := validateRunAgent("kimi"); err != nil {
		t.Fatalf("kimi rejected: %v", err)
	}
	if !isAgentName("kimi") {
		t.Fatal("kimi is not an agent name")
	}
}

func TestCreateKimiUsesDefaultImage(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--name", "kimi", "kimi", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.request.Agent != "kimi" || sandbox.request.Image != agentImage("kimi") {
		t.Fatalf("request=%+v", sandbox.request)
	}
}

func TestRunKimiUsesAgentCommand(t *testing.T) {
	workspace := t.TempDir()
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--name", "kimi", "kimi", workspace}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if sandboxes.created.Agent != "kimi" || sandboxes.created.Image != agentImage("kimi") {
		t.Fatalf("created=%+v", sandboxes.created)
	}
	if len(sessions.req.Argv) == 0 || sessions.req.Argv[0] != "kimi" {
		t.Fatalf("argv=%v", sessions.req.Argv)
	}
}

func TestAgentRegistryPreviewAndUnsupported(t *testing.T) {
	if agentImage("codex") != "ghcr.io/klorq/sandbox-codex:0.1" || agentCommand("codex") != "codex" {
		t.Fatalf("codex image=%q command=%q", agentImage("codex"), agentCommand("codex"))
	}
	if !agentDocker("codex") {
		t.Fatal("codex must enable docker profile")
	}
	if err := validateRunAgent("codex"); err != nil {
		t.Fatalf("preview codex rejected: %v", err)
	}
	if err := validateRunAgent("claude"); err == nil {
		t.Fatal("unsupported claude accepted")
	}
	if err := validateRunAgent("missing"); err == nil {
		t.Fatal("unknown agent accepted")
	}
	if !isAgentName("kimi") || !isAgentName("claude") || isAgentName("missing") {
		t.Fatal("isAgentName registry mismatch")
	}
}

func TestPrivilegedPlumbing(t *testing.T) {
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--docker", "shell"}); code != 0 {
		t.Fatalf("create exit=%d output=%q", code, out.String())
	}
	if !sandbox.request.Privileged {
		t.Fatal("create did not pass privileged")
	}
}
