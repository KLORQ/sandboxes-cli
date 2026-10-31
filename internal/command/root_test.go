package command

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &out, &out); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if out.Len() == 0 {
		t.Fatal("empty output")
	}
}

func TestUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"unknown"}, &out, &out); code != 2 {
		t.Fatalf("exit code %d", code)
	}
}

func TestCreateUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil },
	}
	if code := runner.Run(context.Background(), []string{"create", "dev"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "op-1") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

type fakeExecClient struct{ fakeClient }

func (fakeExecClient) Executor() sdk.Executor { return fakeExecutor{} }

type fakeExecutor struct{}

func (fakeExecutor) Exec(_ context.Context, req sdk.ExecRequest) (int, error) {
	if req.SandboxID != "sb-1" || len(req.Argv) != 2 || req.Argv[0] != "printf" || req.Workdir != "/workspace" {
		return 0, io.ErrUnexpectedEOF
	}
	_, err := io.WriteString(req.Stdout, "fixture")
	return 0, err
}

func TestExecUsesSDKAndResolvesName(t *testing.T) {
	var out, stderr bytes.Buffer
	runner := &Runner{Out: &out, Err: &stderr, NewClient: func(string) (sdk.Client, error) { return fakeExecClient{}, nil }}
	if code := runner.Run(context.Background(), []string{"exec", "-w", "/workspace", "dev", "printf", "fixture"}); code != 0 || out.String() != "fixture" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	if code := runner.Run(context.Background(), []string{"exec", "missing", "true"}); code != 125 {
		t.Fatalf("missing sandbox code=%d", code)
	}
}

func TestListUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil },
	}
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "dev") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestListFollowsPagesAndRejectsCycles(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
			return fakeClient{sandbox: pagedSandbox{cycle: cycle}}, nil
		}}
		code := runner.Run(context.Background(), []string{"ls", "--limit", "1"})
		if cycle {
			if code != 1 || !strings.Contains(out.String(), "invalid sandbox pagination") {
				t.Fatalf("cycle: exit %d, output %q", code, out.String())
			}
			continue
		}
		if code != 0 || !strings.Contains(out.String(), "first") || !strings.Contains(out.String(), "second") {
			t.Fatalf("missing page: exit %d, output %q", code, out.String())
		}
	}
}

func TestWaitFailedOperationReturnsFailure(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{operations: failedOperations{}}, nil
	}}
	if code := runner.Run(context.Background(), []string{"wait", "op-1"}); code != 1 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
}

func TestWaitSuccessfulOperationReturnsSuccess(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"wait", "op-1"}); code != 0 {
		t.Fatalf("exit code %d, output %q", code, out.String())
	}
}

func TestLoginUsesStdinAndDoesNotPrintPassword(t *testing.T) {
	var out bytes.Buffer
	registry := &fakeRegistryCredentials{}
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		In:        strings.NewReader("synthetic-token\n"),
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{registry: registry}, nil },
	}
	if code := runner.Run(context.Background(), []string{"secret", "set", "--registry", "ghcr.io", "--username", "alice", "--password-stdin", "--sandbox", "sample"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if registry.password != "synthetic-token" || registry.request.Scope != sdk.RegistryScopeSandbox || registry.request.SandboxName != "sample" {
		t.Fatalf("unexpected login request: %#v", registry.request)
	}
	if strings.Contains(out.String(), "synthetic-token") || !strings.Contains(out.String(), "ghcr.io") {
		t.Fatalf("login output leaked a secret or omitted registry: %q", out.String())
	}
}

func TestLogoutUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out: &out, Err: &out, Socket: "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{registry: &fakeRegistryCredentials{}}, nil },
	}
	if code := runner.Run(context.Background(), []string{"secret", "rm", "--registry", "ghcr.io", "--all-sandboxes"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "ghcr.io") || strings.Contains(out.String(), "synthetic-token") {
		t.Fatalf("unexpected logout output %q", out.String())
	}
}

func TestAccountCommandsUseAccountService(t *testing.T) {
	for _, command := range []string{"login", "logout"} {
		var out bytes.Buffer
		called := false
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("synthetic-token\n"), NewClient: func(string) (sdk.Client, error) {
			called = true
			return fakeClient{accounts: &fakeAccounts{}}, nil
		}}
		args := []string{command}
		if command == "logout" {
			args = append(args, "--force")
		}
		if code := runner.Run(context.Background(), args); code != 0 || !called {
			t.Fatalf("%s: exit=%d client called=%t output=%q", command, code, called, out.String())
		}
		if strings.Contains(out.String(), "synthetic-token") {
			t.Fatalf("account command consumed or printed registry input: %q", out.String())
		}
		if code := runner.Run(context.Background(), []string{command, "--help"}); code != 0 {
			t.Fatalf("%s --help exit=%d", command, code)
		}
	}
}

func TestLoginDockerPATReadsOneLineFromStdin(t *testing.T) {
	var out bytes.Buffer
	pat := &fakeDockerPATAccounts{}
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("synthetic-token\r\n"), Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{dockerPAT: pat}, nil
	}}
	if code := runner.Run(context.Background(), []string{"login", "--username", "alice", "--password-stdin"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if pat.username != "alice" || string(pat.password) != "synthetic-token" {
		t.Fatalf("unexpected PAT login: %#v", pat)
	}
	if strings.Contains(out.String(), "synthetic-token") || !strings.Contains(out.String(), "Logged in") {
		t.Fatalf("unexpected login output %q", out.String())
	}
}

func TestLoginDockerPATRejectsInvalidStdinWithoutConnecting(t *testing.T) {
	for _, input := range []string{"", "one\ntwo\n", strings.Repeat("x", 2049)} {
		var out bytes.Buffer
		clientCalled := false
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader(input), NewClient: func(string) (sdk.Client, error) {
			clientCalled = true
			return fakeClient{}, nil
		}}
		if code := runner.Run(context.Background(), []string{"login", "--username", "alice", "--password-stdin"}); code != 2 || clientCalled {
			t.Fatalf("input length=%d: exit=%d client-called=%t output=%q", len(input), code, clientCalled, out.String())
		}
	}
}

func TestLogoutForceStopsRunningLocalSandboxes(t *testing.T) {
	var out bytes.Buffer
	sandbox := &logoutSandbox{}
	accounts := &fakeAccounts{}
	runner := &Runner{Out: &out, Err: &out, Socket: "unused", NewClient: func(string) (sdk.Client, error) {
		return fakeClient{sandbox: sandbox, accounts: accounts}, nil
	}}
	if code := runner.Run(context.Background(), []string{"logout", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if sandbox.stops != 1 || !strings.Contains(out.String(), "Stopped 1 running local sandbox") {
		t.Fatalf("logout did not stop the owned running sandbox: stops=%d output=%q", sandbox.stops, out.String())
	}
}

func TestLogoutRequiresConfirmationOrForceInNonTTY(t *testing.T) {
	var out bytes.Buffer
	clientCalled := false
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("y\n"), NewClient: func(string) (sdk.Client, error) {
		clientCalled = true
		return fakeClient{}, nil
	}}
	if code := runner.Run(context.Background(), []string{"logout"}); code != 1 || clientCalled || !strings.Contains(out.String(), "use --force") {
		t.Fatalf("non-TTY logout was not gated: exit=%d called=%t output=%q", code, clientCalled, out.String())
	}
}

func TestSecretRequiresExplicitRegistry(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("synthetic-token\n")}
	for _, subcommand := range []string{"set", "rm"} {
		if code := runner.Run(context.Background(), []string{"secret", subcommand}); code != 2 {
			t.Fatalf("secret %s without registry: exit=%d", subcommand, code)
		}
	}
}

func TestSecretHelpAndAlias(t *testing.T) {
	for _, name := range []string{"secret", "secrets"} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out}
		if code := runner.Run(context.Background(), []string{name, "--help"}); code != 0 {
			t.Fatalf("%s --help: exit=%d, output=%q", name, code, out.String())
		}
		if !strings.Contains(out.String(), "registry credentials only") {
			t.Fatalf("missing current limitation: %q", out.String())
		}
	}
}

type fakeClient struct {
	registry   *fakeRegistryCredentials
	sandbox    sdk.SandboxService
	operations sdk.OperationService
	accounts   sdk.AccountService
	dockerPAT  sdk.DockerPATAccountService
}

func (f fakeClient) DockerPATAccountService() sdk.DockerPATAccountService {
	if f.dockerPAT == nil {
		return nil
	}
	return f.dockerPAT
}

type fakeDockerPATAccounts struct {
	username string
	password []byte
}

func (f *fakeDockerPATAccounts) LoginWithPAT(_ context.Context, username string, password []byte) error {
	f.username = username
	f.password = append(f.password[:0], password...)
	return nil
}

func (f fakeClient) Sandboxes() sdk.SandboxService {
	if f.sandbox != nil {
		return f.sandbox
	}
	return fakeSandbox{}
}
func (f fakeClient) Operations() sdk.OperationService {
	if f.operations != nil {
		return f.operations
	}
	return fakeOperations{}
}
func (f fakeClient) RegistryCredentials() sdk.RegistryCredentialService {
	if f.registry == nil {
		return &fakeRegistryCredentials{}
	}
	return f.registry
}
func (f fakeClient) AccountService() sdk.AccountService {
	if f.accounts == nil {
		return nil
	}
	return f.accounts
}
func (fakeClient) Close() error { return nil }

type fakeAccounts struct{}

func (fakeAccounts) Login(_ context.Context, provider string) error {
	if provider != "docker" {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (fakeAccounts) Logout(_ context.Context, provider string) (bool, error) {
	return provider == "docker", nil
}

type fakeRegistryCredentials struct {
	request  sdk.RegistryLoginRequest
	password string
}

func (f *fakeRegistryCredentials) Login(_ context.Context, req sdk.RegistryLoginRequest) (*sdk.RegistryLoginResponse, error) {
	f.password = string(req.Password)
	f.request = req
	return &sdk.RegistryLoginResponse{Registry: req.Registry, Username: req.Username, Scope: req.Scope, SandboxName: req.SandboxName}, nil
}

func (f *fakeRegistryCredentials) Logout(_ context.Context, req sdk.RegistryLogoutRequest) (*sdk.RegistryLogoutResponse, error) {
	return &sdk.RegistryLogoutResponse{Removed: req.Registry == "ghcr.io"}, nil
}

type fakeSandbox struct{}

type logoutSandbox struct {
	fakeSandbox
	stops int
}

func (*logoutSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-run", Name: "owned", State: sdk.StateRunning}}}, nil
}

func (s *logoutSandbox) Stop(_ context.Context, id string, _ sdk.StopOptions) (*sdk.Operation, error) {
	if id != "sb-run" {
		return nil, io.ErrUnexpectedEOF
	}
	s.stops++
	return &sdk.Operation{ID: "op-stop", Kind: "stop", State: sdk.StateDone}, nil
}

type pagedSandbox struct {
	fakeSandbox
	cycle bool
}

func (s pagedSandbox) List(_ context.Context, opts sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	if opts.PageToken == "" {
		return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{Name: "first"}}, NextPageToken: "next"}, nil
	}
	page := &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{Name: "second"}}}
	if s.cycle {
		page.NextPageToken = "next"
	}
	return page, nil
}

func (fakeSandbox) Create(context.Context, sdk.CreateRequest) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", Kind: "create", State: "done"}, nil
}
func (fakeSandbox) Get(context.Context, string) (*sdk.Sandbox, error) {
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", State: "stopped"}, nil
}
func (fakeSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: "stopped"}}}, nil
}
func (fakeSandbox) Start(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-2", Kind: "start", State: "done"}, nil
}
func (fakeSandbox) Stop(context.Context, string, sdk.StopOptions) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-3", Kind: "stop", State: "done"}, nil
}
func (fakeSandbox) Delete(context.Context, string, sdk.DeleteOptions) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-4", Kind: "delete", State: "done"}, nil
}
func (fakeSandbox) Watch(context.Context, sdk.WatchOptions) (sdk.EventStream, error) {
	return fakeEventStream{}, nil
}

type fakeEventStream struct{}

func (fakeEventStream) Recv() (*sdk.Event, error) { return nil, io.EOF }
func (fakeEventStream) Close() error              { return nil }

type fakeOperations struct{}

type failedOperations struct{ fakeOperations }

func (failedOperations) Wait(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: sdk.StateFailed}, nil
}

func (fakeOperations) Get(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: "done"}, nil
}
func (fakeOperations) Wait(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: "done"}, nil
}

func TestGetResolvesSandboxName(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil }}
	if code := runner.Run(context.Background(), []string{"get", "dev"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "id: sb-1") || !strings.Contains(out.String(), "cpus:") {
		t.Fatalf("unexpected get output: %q", out.String())
	}
}
