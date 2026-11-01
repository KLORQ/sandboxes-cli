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

	"github.com/KLORQ/sandboxes-cli/internal/kit"
)

const (
	answerShortYes = "y"
	answerYes      = "yes"

	actionAllow       = "allow"
	actionDeny        = "deny"
	commandGet        = "get"
	commandInspect    = "inspect"
	commandReset      = "reset"
	stateUnavailable  = "unavailable"
	commandList       = "list"
	commandSet        = "set"
	schemeHTTPS       = "https"
	reasonDefaultDeny = "default deny"
)

const createUsage = `usage: ksbx create [AGENT] [PATH...] [--name NAME] [flags]

Create a sandbox for an agent. The default image is daemon-configured; only the
shell agent is implemented. Omit PATH for no workspace mount.

Flags:
  --name NAME                 sandbox name
  --workspace PATH[:ro]       additional workspace (repeatable)
  -p, --publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6]
                              publish a TCP/UDP guest port (repeatable)
  --allow-network CIDR[:PORT] allow egress (repeatable)
  --deny-network CIDR[:PORT]  deny egress (repeatable)
  -t, --template REF          container image to use for the sandbox
  --image REF                 image override
  --kit FILE                  apply a local kit definition
  --deny-write PATH           mount PATH read-only (repeatable)
  --cpus N                    CPU count for a new sandbox
  --memory SIZE               memory limit (binary units)
  --docker                    run the dedicated Docker profile
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
		return r.flagParseFailure("", err)
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
		return r.version(ctx, rest[1:])
	case "create":
		return r.create(ctx, rest[1:])
	case "ls", commandList:
		return r.list(ctx, rest[1:])
	case commandGet:
		return r.get(ctx, rest[1:])
	case startCommand:
		return r.start(ctx, rest[1:])
	case stopCommand:
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

// flagParseFailure normalizes stdlib flag parse errors to the shared CLI
// error contract: unknown flags exit 1 with a Cobra-style hint, other parse
// failures exit 2. Callers handle flag.ErrHelp before invoking it.
func (r *Runner) flagParseFailure(cmdPath string, err error) int {
	message := err.Error()
	if name, ok := strings.CutPrefix(message, "flag provided but not defined: -"); ok {
		_, _ = fmt.Fprintf(r.Err, "error: unknown flag: --%s\n  try: ksbx %s--help\n", name, commandHintPath(cmdPath))
		return 1
	}
	_, _ = fmt.Fprintf(r.Err, "error: %s\n  try: ksbx %s--help\n", message, commandHintPath(cmdPath))
	return 2
}

func commandHintPath(cmdPath string) string {
	if cmdPath == "" {
		return ""
	}
	return cmdPath + " "
}

//nolint:cyclop,gocyclo // one dispatch switch is the command router.
func (r *Runner) runAuxiliaryCommand(ctx context.Context, name string, args []string) (int, bool) {
	switch name {
	case "run":
		return r.run(ctx, args), true
	case "attach":
		return r.attach(ctx, args), true
	case "exec":
		return r.exec(ctx, args), true
	case "cp":
		return r.cp(ctx, args), true
	case "login":
		return r.accountLogin(ctx, args), true
	case "logout":
		return r.accountLogout(ctx, args), true
	case secretCommand, "secrets":
		return r.secret(ctx, args), true
	case "prune":
		return r.prune(ctx, args), true
	case "diagnose":
		return r.diagnose(ctx, args), true
	case "ports":
		return r.ports(ctx, args), true
	case policyCommand:
		return r.policy(ctx, args), true
	case "settings":
		return r.settings(args), true
	case "kit":
		return r.kit(args), true
	case "daemon":
		return r.daemon(args), true
	case "template":
		return r.template(args), true
	case commandReset:
		return r.reset(ctx, args), true
	case "volume", "env", "mcp", "tui", "move", "ttl", "setup", "skills":
		return r.unsupportedFamily(name), true
	case completionCommand:
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
		return r.flagParseFailure("login", err)
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
		return r.flagParseFailure("logout", err)
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
		_, _ = fmt.Fprintln(r.Out, "usage: ksbx secret <set|ls|rm> [flags]")
		_, _ = fmt.Fprintln(r.Out, "commands: ls, set, rm (service secrets and registry credentials)")
		return 0
	case commandSet:
		if hasFlag(args[1:], "--registry") {
			return r.registrySet(ctx, args[1:])
		}
		return r.serviceSecretSet(ctx, args[1:])
	case "rm":
		if hasFlag(args[1:], "--registry") {
			return r.registryRemove(ctx, args[1:])
		}
		return r.serviceSecretRemove(ctx, args[1:])
	case "ls":
		return r.serviceSecretList(ctx, args[1:])
	case "import":
		return r.serviceSecretImport(ctx, args[1:])
	default:
		_, _ = fmt.Fprintln(r.Err, "unknown secret command")
		return 2
	}
}

// reorderFlagArgs moves flags and their values before positionals so the
// standard library flag parser accepts the Docker sbx flag-after-argument
// grammar. It never interprets values as flags.
func reorderFlagArgs(args []string, valueFlags map[string]bool) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		name, _, hasValue := strings.Cut(arg, "=")
		if hasValue {
			continue
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func (r *Runner) unsupportedFamily(name string) int {
	reasons := map[string]string{
		"volume": "persistent volumes are cloud-only in this build",
		"env":    "declarative sbxenv files are not implemented",
		"mcp":    "the MCP gateway is not implemented",
		"tui":    "the terminal dashboard is not implemented",
		"move":   "cloud move is unavailable without a tenant",
		"ttl":    "cloud TTL is unavailable without a tenant",
		"setup":  "host setup is not implemented",
		"skills": "skills management is not implemented",
	}
	_, _ = fmt.Fprintf(r.Err, "ksbx %s: unsupported: %s\n", name, reasons[name])
	return 1
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || strings.HasPrefix(arg, name+"=") {
			return true
		}
		if arg == "--" {
			return false
		}
	}
	return false
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
		return r.flagParseFailure("secret rm", err)
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
	if code, done := r.parseFlagsOrFail("secret set", fs, args); done {
		return code
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

type flagParseError struct{ err error }

func (e flagParseError) Error() string { return e.err.Error() }

func asFlagParseError(err error) (flagParseError, bool) {
	var parseErr flagParseError
	if errors.As(err, &parseErr) {
		return parseErr, true
	}
	return flagParseError{}, false
}

// parseFlagsOrFail parses a flag set and reports failures through the shared
// error contract, returning done=true when the caller should return code.
func (r *Runner) parseFlagsOrFail(cmdPath string, fs *flag.FlagSet, args []string) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		return r.flagParseFailure(cmdPath, err), true
	}
	return 0, false
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
	privileged     bool
}

func (r *Runner) create(ctx context.Context, args []string) int {
	opts, help, err := parseCreateOptions(ctx, args)
	if help {
		_, _ = fmt.Fprint(r.Out, createUsage)
		return 0
	}
	if parseErr, ok := asFlagParseError(err); ok {
		return r.flagParseFailure("create", parseErr.err)
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
		base := ""
		if len(opts.workspaces) > 0 {
			base = sanitizeNameBase(opts.workspaces[0].Path)
		}
		name, err = runSandboxName(ctx, client, "", opts.agent, base)
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
		Privileged:     opts.privileged,
		Env:            envMap(opts.env),
	})
	if err != nil {
		r.error(err)
		return 1
	}
	r.printCreatedSandbox(ctx, client, name, op)
	return 0
}

// printCreatedSandbox renders the human create summary; operation records stay
// available through --format json on lifecycle commands.
func (r *Runner) printCreatedSandbox(ctx context.Context, client sdk.Client, name string, op *sdk.Operation) {
	id := ""
	if op != nil {
		id = op.SandboxID
	}
	sb, err := lookupSandboxForReport(ctx, client, id, name)
	if err != nil || sb == nil {
		_, _ = fmt.Fprintf(r.Out, "Created sandbox %s\n", name)
		return
	}
	_, _ = fmt.Fprint(r.Out, sandboxReport(sb))
	_, _ = fmt.Fprintf(r.Out, "Created sandbox %s\n", sb.Name)
}

// lookupSandboxForReport resolves a sandbox by ID first and falls back to name.
func lookupSandboxForReport(ctx context.Context, client sdk.Client, id, name string) (*sdk.Sandbox, error) {
	if id != "" {
		sb, err := client.Sandboxes().Get(ctx, id)
		if err == nil {
			return sb, nil
		}
	}
	sb, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("sandbox %q not found", name)
	}
	return sb, nil
}

// sandboxReport formats a created sandbox like the Docker sbx baseline.
func sandboxReport(sb *sdk.Sandbox) string {
	agent := formatAgent(sb.Agent)
	return fmt.Sprintf(`
SANDBOX
  Name:       %s
  Agent:      %s
  Workspace:  %s
  Image:      %s
  CPU:        %d
  Memory:     %s

`, sb.Name, agent, formatWorkspaces(sb), sb.Image, sb.CPUs, formatMemoryMiB(sb.MemoryMiB))
}

// formatMemoryMiB renders memory sizes like the Docker sbx baseline.
func formatMemoryMiB(mib uint32) string {
	if mib == 0 {
		return "-"
	}
	if mib%1024 == 0 {
		return fmt.Sprintf("%d GiB", mib/1024)
	}
	return fmt.Sprintf("%d MiB", mib)
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

// resolveTemplateImage applies the Docker sbx baseline --template alias.
func resolveTemplateImage(image, template string) (string, error) {
	if template == "" {
		return image, nil
	}
	if image != "" {
		return "", errors.New("--template and --image cannot be combined")
	}
	return template, nil
}

func validateCreateResources(cpus uint, memory string) (uint32, uint32, error) {
	cpuCount, err := validateCPUs(cpus)
	if err != nil {
		return 0, 0, err
	}
	memoryMiB, err := parseMemoryMiB(memory)
	if err != nil {
		return 0, 0, err
	}
	return cpuCount, memoryMiB, nil
}

func resolveCreateWorkspaces(workspaceFlags stringListFlag, paths []string) ([]sdk.Workspace, error) {
	combined := make(stringListFlag, 0, len(workspaceFlags)+len(paths))
	combined = append(combined, workspaceFlags...)
	combined = append(combined, paths...)
	return resolveWorkspaces(combined, false)
}

//nolint:gocyclo,cyclop,funlen // create accepts the full documented flag matrix.
func parseCreateOptions(ctx context.Context, args []string) (createOptions, bool, error) {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "", "image reference")
	template := fs.String("template", "", "container image to use for the sandbox (alias for --image)")
	fs.StringVar(template, "t", "", "container image to use for the sandbox (alias for --image)")
	nameFlag := fs.String("name", "", "sandbox name")
	var workspaceFlags stringListFlag
	fs.Var(&workspaceFlags, "workspace", "host workspace path, optionally suffixed with :ro (repeatable)")
	var publishFlags stringListFlag
	fs.Var(&publishFlags, "publish", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable)")
	fs.Var(&publishFlags, "p", "publish [[HOST_IP:]HOST_PORT:]GUEST[/tcp|udp|tcp4|udp4|tcp6|udp6] (repeatable; alias for --publish)")
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
	privileged := fs.Bool("docker", false, "run the dedicated Docker profile")
	kitPath := fs.String("kit", "", "apply a local kit definition")
	var denyWriteFlags stringListFlag
	fs.Var(&denyWriteFlags, "deny-write", "mount PATH read-only (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return createOptions{}, true, nil
		}
		return createOptions{}, false, flagParseError{err: err}
	}
	positionals := fs.Args()
	if *kitPath != "" && len(positionals) == 0 {
		doc, err := kit.Load(*kitPath)
		if err != nil {
			return createOptions{}, false, err
		}
		if doc.Spec.Agent == "" {
			return createOptions{}, false, fmt.Errorf("kit %s does not define an agent", *kitPath)
		}
		positionals = []string{doc.Spec.Agent}
	}
	name, agent, paths, err := parseCreatePositionals(positionals, *nameFlag)
	if err != nil {
		return createOptions{}, false, err
	}
	imageRef, err := resolveTemplateImage(*image, *template)
	if err != nil {
		return createOptions{}, false, err
	}
	if *kitPath != "" {
		kitPaths := []string(workspaceFlags)
		if err := applyKit(ctx, *kitPath, &agent, &imageRef, profile, &kitPaths); err != nil {
			return createOptions{}, false, err
		}
		workspaceFlags = kitPaths
	}
	applyAgentDefaults(agent, &imageRef, privileged)
	cpuCount, memoryMiB, err := validateCreateResources(*cpus, *memory)
	if err != nil {
		return createOptions{}, false, err
	}
	for _, target := range denyWriteFlags {
		workspaceFlags = append(workspaceFlags, target+":ro")
	}
	workspaces, err := resolveCreateWorkspaces(workspaceFlags, paths)
	if err != nil {
		return createOptions{}, false, err
	}
	env, err := buildExecEnv(envFlags, envFileFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	ports, allow, deny, err := resolveCreateNetwork(publishFlags, allowFlags, denyFlags)
	if err != nil {
		return createOptions{}, false, err
	}
	workspace := ""
	if len(workspaces) > 0 {
		workspace = workspaces[0].Path
	}
	return createOptions{
		name: name, agent: agent, image: imageRef, workspace: workspace, idempotencyKey: *idempotency,
		workspaces: workspaces, ports: ports, allow: allow, deny: deny,
		cpus: cpuCount, memoryMiB: memoryMiB, env: env, profile: *profile, privileged: *privileged,
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
	targets, code := r.prepareRemoval(ctx, client, opts)
	if code >= 0 {
		return code
	}
	operations, removed, failed := r.deleteSandboxes(ctx, client, targets)
	if code := r.renderRemoval(opts.format, operations, removed); code >= 0 {
		return code
	}
	if failed {
		return 1
	}
	return 0
}

func (r *Runner) prepareRemoval(ctx context.Context, client sdk.Client, opts removeOptions) ([]string, int) {
	targets := opts.targets
	if opts.all {
		var err error
		targets, err = allSandboxIDs(ctx, client)
		if err != nil {
			r.error(err)
			return nil, 1
		}
	}
	if len(targets) == 0 {
		if err := renderOperations(r.Out, opts.format, nil); err != nil {
			r.error(err)
			return nil, 1
		}
		return nil, 0
	}
	if opts.force {
		return targets, -1
	}
	confirmed, err := r.confirmRemoval(len(targets))
	if err != nil {
		r.error(err)
		return nil, 1
	}
	if !confirmed {
		_, _ = fmt.Fprintln(r.Out, "Removal canceled")
		return nil, 0
	}
	return targets, -1
}

func (r *Runner) renderRemoval(format string, operations []*sdk.Operation, removed []string) int {
	if format != listFormatTable {
		if err := renderOperations(r.Out, format, operations); err != nil {
			r.error(err)
			return 1
		}
		return -1
	}
	for _, name := range removed {
		_, _ = fmt.Fprintf(r.Out, "Removed sandbox %s\n", name)
	}
	return -1
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

func (r *Runner) deleteSandboxes(ctx context.Context, client sdk.Client, targets []string) ([]*sdk.Operation, []string, bool) {
	failed := false
	operations := make([]*sdk.Operation, 0, len(targets))
	removed := make([]string, 0, len(targets))
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
		removed = append(removed, name)
	}
	return operations, removed, failed
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
		return r.flagParseFailure(name, err)
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
		op, err := r.runLifecycleTarget(ctx, client, name, target, *grace)
		if err != nil {
			r.error(err)
			failed = true
			continue
		}
		operations = append(operations, op)
		if selected == listFormatTable {
			_, _ = fmt.Fprintf(r.Out, "%s sandbox %s\n", lifecyclePastTense(name), target)
		}
	}
	if selected != listFormatTable {
		if err := renderOperations(r.Out, selected, operations); err != nil {
			r.error(err)
			return 1
		}
	}
	if failed {
		return 1
	}
	return 0
}

// runLifecycleTarget starts or stops one sandbox and returns its operation.
func (r *Runner) runLifecycleTarget(ctx context.Context, client sdk.Client, name, target string, grace time.Duration) (*sdk.Operation, error) {
	id, err := findExecSandbox(ctx, client, target)
	if err != nil {
		return nil, err
	}
	var op *sdk.Operation
	if name == startCommand {
		op, err = client.Sandboxes().Start(ctx, id)
	} else {
		op, err = client.Sandboxes().Stop(ctx, id, sdk.StopOptions{Grace: grace})
	}
	if err != nil {
		return nil, err
	}
	if op != nil && op.State == sdk.StateFailed {
		return nil, fmt.Errorf("%s sandbox %s failed: %s", name, target, op.Error)
	}
	return op, nil
}

func lifecyclePastTense(name string) string {
	switch name {
	case stopCommand:
		return "Stopped"
	case startCommand:
		return "Started"
	default:
		return name + "ed"
	}
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
	_, _ = fmt.Fprintln(r.Out, "commands: run, attach, create, exec, cp, ls, get, ports, policy, settings, kit, daemon, start, stop, rm, prune, diagnose, wait, login, logout, secret, completion, version, help")
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
