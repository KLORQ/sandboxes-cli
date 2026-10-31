package command

import (
	"bytes"
	"context"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestProfileRules(t *testing.T) {
	for _, tc := range []struct {
		profile string
		want    int
		bad     bool
	}{
		{"", 0, false},
		{"deny-all", 0, false},
		{"balanced", 4, false},
		{"sbx-compat", 2, false},
		{"unknown", 0, true},
	} {
		rules, err := profileRules(tc.profile)
		if (err != nil) != tc.bad || len(rules) != tc.want {
			t.Fatalf("profile %q rules=%d err=%v", tc.profile, len(rules), err)
		}
	}
}

func TestCreatePolicyProfile(t *testing.T) {
	workspace := t.TempDir()
	sandbox := &recordingCreateSandbox{}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil }}
	if code := runner.Run(context.Background(), []string{"create", "--policy-profile", "sbx-compat", "--name", "compat", "shell", workspace}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.request.Allow) != 2 {
		t.Fatalf("allow=%+v", sandbox.request.Allow)
	}
}

func TestCreateRejectsUnknownPolicyProfile(t *testing.T) {
	called := false
	runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
		called = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"create", "--policy-profile", "unknown", "shell"}); code != 2 || called {
		t.Fatalf("exit=%d client=%t", code, called)
	}
}

func TestRunPolicyProfile(t *testing.T) {
	sandboxes := &runSandbox{}
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, runClient{sandboxes: sandboxes, sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"run", "--policy-profile", "balanced", "--name", "balanced", "shell", t.TempDir()}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(sandboxes.created.Allow) != 4 {
		t.Fatalf("allow=%+v", sandboxes.created.Allow)
	}
}
