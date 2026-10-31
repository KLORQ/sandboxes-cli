// Package command implements the CLI command tree.
package command

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	sdk "github.com/KLORQ/sandboxes-go-sdk"

	"github.com/KLORQ/sandboxes-cli/internal/version"
)

const (
	answerShortYes = "y"
	answerYes      = "yes"
)

const createUsage = `usage: ksbx create [AGENT] [PATH...] [--name NAME] [flags]

Create a sandbox for an agent. The default image is daemon-configured; only the
shell agent is implemented. Omit PATH for no workspace mount.

Flags:
  --name NAME                 sandbox name
  --workspace PATH[:ro]       additional workspace (repeatable)
  --publish HOST:GUEST[/tcp|udp]  publish a TCP/UDP guest port (repeatable)
  --allow-network CIDR[:PORT] allow egress (repeatable)
  --deny-network CIDR[:PORT]  deny egress (repeatable)
  --image REF                 image override
  --cpus N                    CPU count for a new sandbox
  --memory SIZE               memory limit (binary units)
  --idempotency-key KEY       idempotency key
  -e, --env KEY=VALUE         environment for every process (repeatable)
  --env-file FILE             read environment overrides from a file (repeatable)
`

const removeUsage = `usage: ksbx rm [-f|--force] [--format table|json|yaml] SANDBOX... | --all

Remove one or more sandboxes. --force skips confirmation and allows removal of
a running sandbox. --all removes every sandbox.
`

const pruneUsage = `usage: ksbx prune [--dry-run] [-f|--force] [--filter until=TIMESTAMP] [--format table|json|yaml]

Remove stopped sandboxes. --dry-run lists candidates without removing them;
--force skips confirmation.
`

// Runner executes commands against a local daemon.
type Runner struct {
	Out       io.Writer
	Err       io.Writer
	In        io.Reader
	Socket    string
	NewClient func(address string) (sdk.Client, error)
}

// NewRunner creates a CLI runner.
func NewRunner(out, errOut io.Writer) *Runner {
	return &Runner{
		Out:       out,
		Err:       errOut,
		In:        os.Stdin,
		Socket:    defaultSocket(),
		NewClient: func(address string) (sdk.Client, error) { return sdk.New(sdk.Config{Address: address}) },
	}
}

// Run executes the CLI.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return NewRunner(stdout, stderr).Run(ctx, args)
}

// Run executes the command tree and returns a process exit code.
func (r *Runner) Run(ctx context.Context, args []string) int {
	global := flag.NewFlagSet("ksbx", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	socket := global.String("socket", r.Socket, "daemon unix socket")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			r.usage()
			return 0
		}
		return 2
	}
	r.Socket = *socket
	rest := global.Args()
	if len(rest) == 0 {
		r.usage()
		return 2
	}
	if code, handled := r.runAuxiliaryCommand(ctx, rest[0], rest[1:]); handled {
		return code
	}

	switch rest[0] {
	case helpCommand, helpShort, helpFlag:
		r.usage()
		return 0
	case "version":
		_, _ = fmt.Fprintln(r.Out, version.Version)
		return 0
	case "create":
		return r.create(ctx, rest[1:])
	case "ls", "list":
		return r.list(ctx, rest[1:])
	case "get":
		return r.get(ctx, rest[1:])
	case "start":
		return r.start(ctx, rest[1:])
	case "stop":
		return r.stop(ctx, rest[1:])
	case "rm", "delete":
		return r.remove(ctx, rest[1:])
	case "wait":
		return r.wait(ctx, rest[1:])
	default:
		_, _ = fmt.Fprintf(r.Err, "unknown command: %s\n", rest[0])
		r.usage()
		return 2
	}
}

func (r *Runner) runAuxiliaryCommand(ctx context.Context, name string, args []string) (int, bool) {
	switch name {
	case "run":
		return r.run(ctx, args), true
	case "exec":
		return r.exec(ctx, args), true
	case "cp":
		return r.cp(ctx, args), true
	case "login":
		return r.accountLogin(ctx, args), true
	case "logout":
		return r.accountLogout(ctx, args), true
	case "secret", "secrets":
		return r.secret(ctx, args), true
	case "prune":
		return r.prune(ctx, args), true
	case "diagnose":
		return r.diagnose(ctx, args), true
	case "ports":
		return r.ports(ctx, args), true
	case "policy":
		return r.policy(ctx, args), true
	case "completion":
		return r.completion(args), true
	default:
		return 0, false
	}
}

func (r *Runner) accountLogin(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	username := fs.String("username", "", "Docker Hub username for PAT login")
	passwordStdin := fs.Bool("password-stdin", false, "read Docker Hub password or PAT from stdin")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || (*username == "") != !*passwordStdin {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx login [--username USER --password-stdin]")
		return 2
	}
	var password []byte
	if *passwordStdin {
		var err error
		password, err = readDockerPassword(r.In)
		if err != nil {
			r.error(err)
			return 2
		}
		defer clear(password)
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if *passwordStdin {
		if err := sdk.DockerPATAccounts(client).LoginWithPAT(ctx, *username, password); err != nil {
			r.error(err)
			return 1
		}
		_, _ = fmt.Fprintln(r.Out, "Logged in to Docker account")
		return 0
	}
	_, _ = fmt.Fprintln(r.Err, "Opening Docker sign-in in your browser. Complete the authorization to finish login.")
	if err := sdk.Accounts(client).Login(ctx, "docker"); err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintln(r.Out, "Logged in to Docker account")
	return 0
}

func readDockerPassword(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, errors.New("password stdin is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		clear(raw)
		return nil, errors.New("read Docker Hub password from stdin failed")
	}
	defer clear(raw)
	if len(raw) > 2048 {
		return nil, errors.New("password exceeds 2048 bytes for Docker Hub")
	}
	end := len(raw)
	if end > 0 && raw[end-1] == '\n' {
		end--
		if end > 0 && raw[end-1] == '\r' {
			end--
		}
	}
	password := raw[:end]
	if len(password) == 0 || bytes.ContainsAny(password, "\r\n\x00") {
		return nil, errors.New("stdin must contain one non-empty Docker Hub password line")
	}
	return append([]byte(nil), password...), nil
}

func (r *Runner) accountLogout(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	force := fs.Bool("force", false, "skip confirmation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx logout [--force]")
		return 2
	}
	if !*force {
		confirmed, err := r.confirmLogout()
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Logout canceled")
			return 0
		}
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	stopped, err := r.stopRunningSandboxes(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	removed, err := sdk.Accounts(client).Logout(ctx, "docker")
	if err != nil {
		r.error(err)
		return 1
	}
	if removed {
		_, _ = fmt.Fprintln(r.Out, "Removed local Docker account credentials")
	} else {
		_, _ = fmt.Fprintln(r.Out, "No local Docker account credentials found")
	}
	if stopped > 0 {
		_, _ = fmt.Fprintf(r.Out, "Stopped %d running local sandbox(es)\n", stopped)
	}
	return 0
}

func (r *Runner) confirmLogout() (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, fmt.Errorf("logout confirmation requires a terminal; use --force to skip confirmation")
	}
	if _, err := fmt.Fprint(r.Err, "Stop running local sandboxes and sign out? [y/N] "); err != nil {
		return false, fmt.Errorf("write logout prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read logout confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

func (r *Runner) stopRunningSandboxes(ctx context.Context, client sdk.Client) (int, error) {
	stopped, seenPages := 0, make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return stopped, fmt.Errorf("list local sandboxes before logout: %w", err)
		}
		pageCount, err := r.stopSandboxesOnPage(ctx, client, page.Items)
		stopped += pageCount
		if err != nil {
			return stopped, err
		}
		if page.NextPageToken == "" {
			return stopped, nil
		}
		if _, ok := seenPages[page.NextPageToken]; ok {
			return stopped, fmt.Errorf("daemon returned a repeated sandbox page token")
		}
		seenPages[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return stopped, fmt.Errorf("daemon returned too many sandbox pages")
}

func (r *Runner) stopSandboxesOnPage(ctx context.Context, client sdk.Client, items []sdk.Sandbox) (int, error) {
	stopped := 0
	for i := range items {
		sandbox := &items[i]
		if sandbox.State != sdk.StateRunning {
			continue
		}
		if err := r.stopSandbox(ctx, client, sandbox); err != nil {
			return stopped, err
		}
		stopped++
	}
	return stopped, nil
}

func (r *Runner) stopSandbox(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	op, err := client.Sandboxes().Stop(ctx, sandbox.ID, sdk.StopOptions{})
	if err != nil {
		return fmt.Errorf("stop sandbox %s before logout: %w", sandbox.Name, err)
	}
	if op == nil || op.ID == "" {
		return nil
	}
	completed, err := client.Operations().Wait(ctx, op.ID)
	if err != nil {
		return fmt.Errorf("wait for sandbox %s to stop: %w", sandbox.Name, err)
	}
	if completed != nil && completed.State == sdk.StateFailed {
		return fmt.Errorf("sandbox %s failed to stop", sandbox.Name)
	}
	return nil
}

func (r *Runner) secret(ctx context.Context, args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret <set|rm> [flags]")
		return 2
	}
	switch args[0] {
	case helpCommand, helpShort, helpFlag:
		_, _ = fmt.Fprintln(r.Out, "usage: ksbx secret <set|rm> [flags]")
		_, _ = fmt.Fprintln(r.Out, "commands: ls, set, rm (registry credentials only)")
		return 0
	case "set":
		return r.registrySet(ctx, args[1:])
	case "rm":
		return r.registryRemove(ctx, args[1:])
	case "ls":
		return r.registryList(ctx, args[1:])
	default:
		_, _ = fmt.Fprintln(r.Err, "unknown secret command")
		return 2
	}
}

func (r *Runner) registryRemove(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	registry := fs.String("registry", "", "registry host")
	allSandboxes := fs.Bool("all-sandboxes", false, "remove all-sandboxes credential")
	sandboxName := fs.String("sandbox", "", "remove credential for one sandbox")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *registry == "" || *allSandboxes && *sandboxName != "" {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret rm [--registry HOST] [--all-sandboxes | --sandbox NAME]")
		return 2
	}
	scope := sdk.RegistryScopeHostOnly
	if *allSandboxes {
		scope = sdk.RegistryScopeAllSandboxes
	} else if *sandboxName != "" {
		scope = sdk.RegistryScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	response, err := client.RegistryCredentials().Logout(ctx, sdk.RegistryLogoutRequest{
		Registry: *registry, Scope: scope, SandboxName: *sandboxName,
	})
	if err != nil {
		r.error(err)
		return 1
	}
	if response.Removed {
		_, _ = fmt.Fprintf(r.Out, "Removed registry credentials for %s (%s)\n", *registry, scope)
	} else {
		_, _ = fmt.Fprintf(r.Out, "No registry credentials stored for %s (%s)\n", *registry, scope)
	}
	return 0
}

func (r *Runner) registrySet(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	registry := fs.String("registry", "", "registry host")
	username := fs.String("username", "", "registry username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	allSandboxes := fs.Bool("all-sandboxes", false, "allow future brokered use in all sandboxes")
	sandboxName := fs.String("sandbox", "", "allow future brokered use in one sandbox")
	if err := fs.Parse(args); err != nil {
		return flagErrorCode(err)
	}
	if !validRegistryArguments(fs.NArg(), *registry) {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx secret set [--registry HOST] --username USER [--password-stdin] [--all-sandboxes | --sandbox NAME]")
		return 2
	}
	if *allSandboxes && *sandboxName != "" {
		_, _ = fmt.Fprintln(r.Err, "--all-sandboxes and --sandbox cannot be combined")
		return 2
	}
	if *username == "" {
		if *passwordStdin {
			_, _ = fmt.Fprintln(r.Err, "--username is required with --password-stdin")
			return 2
		}
		if _, err := fmt.Fprint(r.Err, "Username: "); err != nil {
			r.error(err)
			return 1
		}
		line, err := bufio.NewReader(r.In).ReadString('\n')
		if err != nil && line == "" {
			r.error(fmt.Errorf("read username: %w", err))
			return 1
		}
		*username = strings.TrimSpace(line)
	}
	password, err := r.readLoginPassword(*passwordStdin)
	if err != nil {
		r.error(err)
		return 2
	}
	defer clear(password)
	scope := sdk.RegistryScopeHostOnly
	if *allSandboxes {
		scope = sdk.RegistryScopeAllSandboxes
	} else if *sandboxName != "" {
		scope = sdk.RegistryScopeSandbox
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	response, err := client.RegistryCredentials().Login(ctx, sdk.RegistryLoginRequest{
		Registry: *registry, Username: *username, Password: password,
		Scope: scope, SandboxName: *sandboxName,
	})
	if err != nil {
		r.error(err)
		return 1
	}
	_, _ = fmt.Fprintf(r.Out, "Credentials stored (not verified) in host keychain for %s as %s (%s); sandbox registry access is not enabled yet\n", response.Registry, response.Username, response.Scope)
	return 0
}

func flagErrorCode(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

func validRegistryArguments(count int, registry string) bool {
	return count == 0 && registry != ""
}

func (r *Runner) readLoginPassword(fromStdin bool) ([]byte, error) {
	if file, ok := r.In.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		if fromStdin {
			return nil, fmt.Errorf("refusing to read --password-stdin from an interactive terminal; omit the flag for hidden prompt")
		}
		if _, err := fmt.Fprint(r.Err, "Password: "); err != nil {
			return nil, fmt.Errorf("write password prompt: %w", err)
		}
		password, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(r.Err)
		if err != nil {
			return nil, fmt.Errorf("read password from terminal: %w", err)
		}
		return password, nil
	}
	if !fromStdin {
		return nil, fmt.Errorf("password input is not a terminal; use --password-stdin")
	}
	data, err := io.ReadAll(io.LimitReader(r.In, 2050))
	if err != nil {
		clear(data)
		return nil, fmt.Errorf("read password from stdin: %w", err)
	}
	if len(data) > 2049 {
		clear(data)
		return nil, fmt.Errorf("password exceeds the 2048-byte limit")
	}
	data = bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	if len(data) == 0 || len(data) > 2048 || bytes.ContainsAny(data, "\r\n") {
		clear(data)
		return nil, fmt.Errorf("password input must contain one non-empty line up to 2048 bytes")
	}
	return data, nil
}

type createOptions struct {
	name           string
	agent          string
	image          string
	workspace      string
	idempotencyKey string
	workspaces     []sdk.Workspace
	ports          []sdk.Port
	allow          []sdk.NetworkRule
	deny           []sdk.NetworkRule
	cpus           uint32
	memoryMiB      uint32
	env            []string
	profile        string
}

func (r *Runner) create(ctx context.Context, args []string) int {
	opts, help, err := parseCreateOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, createUsage)
		return 0
	}
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	name := opts.name
	if name == "" {
		name, err = runSandboxName(ctx, client, "", opts.agent)
		if err != nil {
			r.error(err)
			return 1
		}
	}
	op, err := client.Sandboxes().Create(ctx, sdk.CreateRequest{
		Name:           name,
		Image:          opts.image,
		Workspace:      opts.workspace,
		Workspaces:     opts.workspaces,
		Ports:          opts.ports,
		Allow:          opts.allow,
		Deny:           opts.deny,
		IdempotencyKey: opts.idempotencyKey,
		Agent:          opts.agent,
		CPUs:           opts.cpus,
		MemoryMiB:      opts.memoryMiB,
		PolicyProfile:  opts.profile,
		Env:            envMap(opts.env),
	})
	if err != nil {
		r.error(err)
		return 1
	}
	r.printOperation(op)
	return 0
}

func parseCreatePositionals(positionals []string, nameFlag string) (string, string, []string, error) {
	if len(positionals) == 0 {
		return "", "", nil, errors.New("usage: ksbx create [AGENT] [PATH...] [--name NAME] [--cpus N] [--memory SIZE] [--image REF]")
	}
	agent := ""
	paths := []string(nil)
	name := nameFlag
	if isAgentName(positionals[0]) {
		agent = positionals[0]
		paths = positionals[1:]
	} else {
		if name != "" {
			return "", "", nil, errors.New("--name requires an agent argument (for example: ksbx create --name dev shell PATH)")
		}
		name = positionals[0]
		paths = positionals[1:]
	}
	if agent != "" {
		if err := validateRunAgent(agent); err != nil {
			return "", "", nil, err
		}
	}
	return name, agent, paths, nil
}

func parseCreateOptions(args []string) (createOptions, bool, error) {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "", "image reference")
	nameFlag := fs.String("name", "", "sandbox name")
	var workspaceFlags stringListFlag
	fs.Var(&workspaceFlags, "workspace", "host workspace path, optionally suffixed with :ro (repeatable)")
	var publishFlags stringListFlag
	fs.Var(&publishFlags, "publish", "publish HOST:GUEST[/tcp|udp] (repeatable)")
	var allowFlags, denyFlags stringListFlag
	fs.Var(&allowFlags, "allow-network", "allow egress CIDR[:PORT] (repeatable; optional udp: prefix)")
	fs.Var(&denyFlags, "deny-network", "deny egress CIDR[:PORT] (repeatable; optional udp: prefix)")
	var envFlags, envFileFlags stringListFlag
	fs.Var(&envFlags, "env", "environment KEY=VALUE for every process (repeatable)")
	fs.Var(&envFlags, "e", "environment KEY=VALUE for every process (repeatable)")
	fs.Var(&envFileFlags, "env-file", "read environment from a file (repeatable)")
	idempotency := fs.String("idempotency-key", "", "idempotency key")
	cpus := fs.Uint("cpus", 0, "CPUs (0 selects the daemon default)")
	memory := fs.String("memory", "", "memory limit such as 512m or 2g (empty selects the daemon default)")
	profile := fs.String("policy-profile", "", "egress profile: deny-all, balanced or sbx-compat")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return createOptions{}, true, nil
		}
		return createOptions{}, false, err
	}
	name, agent, paths, err := parseCreatePositionals(fs.Args(), *nameFlag)
	if err != nil {
		return createOptions{}, false, err
	}
	cpuCount, err := validateCPUs(*cpus)
	if err != nil {
		return createOptions{}, false, err
	}
	memoryMiB, err := parseMemoryMiB(*memory)
	if err != nil {
		return createOptions{}, false, err
	}
	combinedWorkspaces := make(stringListFlag, 0, len(workspaceFlags)+len(paths))
	combinedWorkspaces = append(combinedWorkspaces, workspaceFlags...)
	combinedWorkspaces = append(combinedWorkspaces, paths...)
	workspaces, err := resolveWorkspaces(combinedWorkspaces, false)
	if err != nil {
		return createOptions{}, false, err
	}
	env, err := buildExecEnv(envFlags, envFileFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	workspace := firstWorkspacePath(workspaces)
	ports, allow, deny, err := resolveCreateNetwork(publishFlags, allowFlags, denyFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	return createOptions{
		name: name, agent: agent, image: *image, workspace: workspace, idempotencyKey: *idempotency,
		workspaces: workspaces, ports: ports, allow: allow, deny: deny,
		cpus: cpuCount, memoryMiB: memoryMiB, env: env, profile: *profile,
	}, false, nil
}

func (r *Runner) get(ctx context.Context, args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx get <id>")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	sb, err := client.Sandboxes().Get(ctx, id)
	if err != nil {
		r.error(err)
		return 1
	}
	r.printSandbox(sb)
	return 0
}

func (r *Runner) start(ctx context.Context, args []string) int {
	return r.lifecycle(ctx, "start", args)
}

func (r *Runner) stop(ctx context.Context, args []string) int {
	return r.lifecycle(ctx, "stop", args)
}

type removeOptions struct {
	force   bool
	all     bool
	format  string
	targets []string
}

func (r *Runner) remove(ctx context.Context, args []string) int {
	opts, help, err := parseRemoveOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, removeUsage)
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "ksbx rm: %v\n", err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	targets := opts.targets
	if opts.all {
		targets, err = allSandboxIDs(ctx, client)
		if err != nil {
			r.error(err)
			return 1
		}
	}
	if len(targets) == 0 {
		if err := renderOperations(r.Out, opts.format, nil); err != nil {
			r.error(err)
			return 1
		}
		return 0
	}
	if !opts.force {
		confirmed, err := r.confirmRemoval(len(targets))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Removal canceled")
			return 0
		}
	}
	operations, failed := r.deleteSandboxes(ctx, client, targets)
	if err := renderOperations(r.Out, opts.format, operations); err != nil {
		r.error(err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func parseRemoveOptions(args []string) (removeOptions, bool, error) {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "delete without confirmation and allow running sandboxes")
	fs.BoolVar(force, "f", false, "delete without confirmation and allow running sandboxes")
	all := fs.Bool("all", false, "remove all sandboxes")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return removeOptions{}, true, nil
		}
		return removeOptions{}, false, err
	}
	if (*all && fs.NArg() != 0) || (!*all && fs.NArg() < 1) {
		return removeOptions{}, false, errors.New("usage: ksbx rm [-f|--force] [--format table|json|yaml] SANDBOX... | --all")
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		return removeOptions{}, false, err
	}
	return removeOptions{force: *force, all: *all, format: selected, targets: fs.Args()}, false, nil
}

func allSandboxIDs(ctx context.Context, client sdk.Client) ([]string, error) {
	items, err := collectSandboxes(ctx, client, 200)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(items))
	for i := range items {
		ids = append(ids, items[i].ID)
	}
	return ids, nil
}

func (r *Runner) deleteSandboxes(ctx context.Context, client sdk.Client, targets []string) ([]*sdk.Operation, bool) {
	failed := false
	operations := make([]*sdk.Operation, 0, len(targets))
	for _, name := range targets {
		id, err := findExecSandbox(ctx, client, name)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		op, err := client.Sandboxes().Delete(ctx, id, sdk.DeleteOptions{Force: true})
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		if op != nil && op.State == sdk.StateFailed {
			r.error(fmt.Errorf("remove sandbox %s failed: %s", name, op.Error))
			failed = true
			continue
		}
		operations = append(operations, op)
	}
	return operations, failed
}

func (r *Runner) confirmRemoval(count int) (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, errors.New("removal confirmation requires a terminal; use --force to skip confirmation")
	}
	if _, err := fmt.Fprintf(r.Err, "Remove %d sandbox(es)? [y/N] ", count); err != nil {
		return false, fmt.Errorf("write removal prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read removal confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}

func (r *Runner) wait(ctx context.Context, args []string) int {
	if len(args) != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx wait <operation-id>")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	op, err := client.Operations().Wait(ctx, args[0])
	if err != nil {
		r.error(err)
		return 1
	}
	r.printOperation(op)
	if op != nil && op.State == sdk.StateFailed {
		return 1
	}
	return 0
}

func (r *Runner) lifecycle(ctx context.Context, name string, args []string) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(r.Err)
	grace := fs.Duration("grace", 0, "grace period")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() < 1 {
		_, _ = fmt.Fprintf(r.Err, "usage: ksbx %s [--format table|json|yaml] [--json] [flags] SANDBOX...\n", name)
		return 2
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		r.error(err)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	failed := false
	var operations []*sdk.Operation
	for _, target := range fs.Args() {
		id, err := findExecSandbox(ctx, client, target)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		var op *sdk.Operation
		if name == "start" {
			op, err = client.Sandboxes().Start(ctx, id)
		} else {
			op, err = client.Sandboxes().Stop(ctx, id, sdk.StopOptions{Grace: *grace})
		}
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		if op != nil && op.State == sdk.StateFailed {
			r.error(fmt.Errorf("%s sandbox %s failed: %s", name, target, op.Error))
			failed = true
			continue
		}
		operations = append(operations, op)
	}
	if err := renderOperations(r.Out, selected, operations); err != nil {
		r.error(err)
		return 1
	}
	if failed {
		return 1
	}
	return 0
}

func (r *Runner) client() (sdk.Client, error) {
	if r.NewClient == nil {
		return sdk.New(sdk.Config{Address: r.Socket})
	}
	return r.NewClient(r.Socket)
}

func (r *Runner) printOperation(op *sdk.Operation) {
	if op == nil {
		_, _ = fmt.Fprintln(r.Out, "ok")
		return
	}
	_, _ = fmt.Fprintf(r.Out, "%s\t%s\t%s\t%s\n", op.ID, op.Kind, op.State, op.Error)
}

func (r *Runner) printSandbox(sb *sdk.Sandbox) {
	if sb == nil {
		_, _ = fmt.Fprintln(r.Out, "not found")
		return
	}
	_, _ = fmt.Fprintf(r.Out, "id: %s\nname: %s\nstate: %s\nagent: %s\npolicy_profile: %s\ndetached: %t\nlast_used_at: %s\nimage: %s\nworkspace: %s\nworkspaces: %s\nports: %s\nallow: %s\ndeny: %s\ncpus: %d\nmemory_mib: %d\nstopped_at: %s\ngeneration: %d\ncreated: %s\n",
		sb.ID, sb.Name, sb.State, formatAgent(sb.Agent), sb.PolicyProfile, sb.Detached, formatTime(sb.LastUsedAt), sb.Image, sb.Workspace, formatWorkspaces(sb), formatPorts(sb), formatRules(sb.Allow), formatRules(sb.Deny),
		sb.CPUs, sb.MemoryMiB, formatTime(sb.StoppedAt), sb.Generation, formatTime(sb.CreatedAt))
}

func (r *Runner) usage() {
	_, _ = fmt.Fprintln(r.Out, "usage: ksbx [--socket PATH] <command>")
	_, _ = fmt.Fprintln(r.Out, "commands: run, create, exec, cp, ls, get, ports, policy, start, stop, rm, prune, diagnose, wait, login, logout, secret, completion, version, help")
	_, _ = fmt.Fprintln(r.Out, "global flags: --socket PATH  daemon unix socket")
	_, _ = fmt.Fprintln(r.Out, `Use "ksbx <command> --help" for command details.`)
}

func (r *Runner) error(err error) {
	_, _ = fmt.Fprintln(r.Err, err)
}

func defaultSocket() string {
	if socket := strings.TrimSpace(os.Getenv("SANDBOXES_SOCKET")); socket != "" {
		return socket
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sandboxes/sandboxesd.sock"
	}
	return filepath.Join(home, ".sandboxes", "sandboxesd.sock")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func formatWorkspaces(sb *sdk.Sandbox) string {
	workspaces := sb.Workspaces
	if len(workspaces) == 0 && sb.Workspace != "" {
		workspaces = []sdk.Workspace{{Path: sb.Workspace}}
	}
	if len(workspaces) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(workspaces))
	for i := range workspaces {
		mode := "rw"
		if workspaces[i].ReadOnly {
			mode = "ro"
		}
		parts = append(parts, workspaces[i].Path+" ("+mode+")")
	}
	return strings.Join(parts, ", ")
}

func formatPorts(sb *sdk.Sandbox) string {
	if len(sb.Ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(sb.Ports))
	for i := range sb.Ports {
		protocol := sb.Ports[i].Protocol
		if protocol == "" {
			protocol = tcpProtocol
		}
		parts = append(parts, fmt.Sprintf("%d->%d/%s", sb.Ports[i].Host, sb.Ports[i].Guest, protocol))
	}
	return strings.Join(parts, ", ")
}

func resolveCreateNetwork(publish, allow, deny []string) ([]sdk.Port, []sdk.NetworkRule, []sdk.NetworkRule, error) {
	ports, err := resolvePorts(publish)
	if err != nil {
		return nil, nil, nil, err
	}
	allowRules, err := resolveNetworkRules(allow)
	if err != nil {
		return nil, nil, nil, err
	}
	denyRules, err := resolveNetworkRules(deny)
	if err != nil {
		return nil, nil, nil, err
	}
	return ports, allowRules, denyRules, nil
}

func firstWorkspacePath(workspaces []sdk.Workspace) string {
	if len(workspaces) == 0 {
		return ""
	}
	return workspaces[0].Path
}
