package command

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type recordingExecClient struct {
	fakeClient
	executor *recordingExecutor
}

func (c recordingExecClient) Executor() sdk.Executor { return c.executor }

type recordingExecutor struct{ request sdk.ExecRequest }

func (e *recordingExecutor) Exec(_ context.Context, req sdk.ExecRequest) (int, error) {
	e.request = req
	return 0, nil
}

type sessionCapClient struct {
	fakeClient
	sessions *fakeSessions
}

func (c sessionCapClient) SessionExecutor() sdk.SessionExecutor { return c.sessions }

func TestExecPassesEnvFileEnvAndUser(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "exec.env")
	if err := os.WriteFile(envFile, []byte("FROM_FILE=file\r\n# comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	code := runner.Run(context.Background(), []string{"exec", "--env-file", envFile, "-e", "A=1", "--env", "B=two", "-u", "1000:1001", "dev", "true"})
	if code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if want := []string{"FROM_FILE=file", "A=1", "B=two"}; !reflect.DeepEqual(executor.request.Env, want) {
		t.Fatalf("env=%q want %q", executor.request.Env, want)
	}
	if executor.request.User != "1000:1001" || executor.request.SandboxID != "sb-1" {
		t.Fatalf("unexpected request: %#v", executor.request)
	}
}

func TestExecSessionPassesEnvAndUser(t *testing.T) {
	sessions := &fakeSessions{}
	runner, out, stderr := runTestRunner(t, sessionCapClient{sessions: sessions}, "")
	if code := runner.Run(context.Background(), []string{"exec", "-it", "-e", "A=1", "-u", "0:0", "dev", "/bin/sh"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if !sessions.opened || !reflect.DeepEqual(sessions.req.Env, []string{"A=1"}) || sessions.req.User != "0:0" || !sessions.req.TTY {
		t.Fatalf("unexpected session request: %#v", sessions.req)
	}
}

func TestExecRejectsInvalidEnvAndUserBeforeConnecting(t *testing.T) {
	badFile := filepath.Join(t.TempDir(), "bad.env")
	if err := os.WriteFile(badFile, []byte("whitespace = value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"exec", "-e", "1BAD=x", "dev", "true"},
		{"exec", "-e", "OK=value", "-u", "root:", "dev", "true"},
		{"exec", "--env-file", badFile, "dev", "true"},
	} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, In: strings.NewReader(""), NewClient: func(string) (sdk.Client, error) {
			called = true
			return recordingExecClient{executor: &recordingExecutor{}}, nil
		}}
		if code := runner.Run(context.Background(), args); code != 125 || called {
			t.Fatalf("%v: exit=%d client-called=%t", args, code, called)
		}
	}
}

func TestExpandExecFlagsKeepsValueFlagsAndFollowingFlags(t *testing.T) {
	args := []string{"-e", "A=1", "-w", "/workspace", "--env-file", "file", "-it", "dev", "true"}
	want := []string{"-e", "A=1", "-w", "/workspace", "--env-file", "file", "-i", "-t", "dev", "true"}
	if got := expandExecFlags(args); !reflect.DeepEqual(got, want) {
		t.Fatalf("expandExecFlags=%q want %q", got, want)
	}
}

func TestExecCopiesExplicitHostEnvironment(t *testing.T) {
	t.Setenv("KLORQ_HOST_COPY_TEST", "host-value")
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	if code := runner.Run(context.Background(), []string{"exec", "-e", "KLORQ_HOST_COPY_TEST", "dev", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(executor.request.Env) != 1 || executor.request.Env[0] != "KLORQ_HOST_COPY_TEST=host-value" {
		t.Fatalf("env=%q", executor.request.Env)
	}
}

func TestExecSkipsUnsetBareHostEnvironment(t *testing.T) {
	executor := &recordingExecutor{}
	runner, out, stderr := runTestRunner(t, recordingExecClient{executor: executor}, "")
	if code := runner.Run(context.Background(), []string{"exec", "-e", "KLORQ_DEFINITELY_UNSET_ENV", "dev", "true"}); code != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if len(executor.request.Env) != 0 {
		t.Fatalf("env=%q", executor.request.Env)
	}
}
