package command

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const (
	runUsage = `usage: ksbx run [flags] [AGENT] [PATH] [-- AGENT_ARGS...]

Create a sandbox (or reuse one by --name), start it, and attach to an agent.
The default workspace is the current directory. With --detach the sandbox is
created and started, and its ID is printed without attaching.

Agents:
  shell, kimi              available
  codex, gemini, opencode  preview (official image, not live-tested)
  claude, cline, copilot, cursor, devin, docker-agent, droid, kiro
                           unsupported

Flags:
      --name NAME   sandbox name; reuse and restart it when it already exists
  -d, --detach      create and start without attaching
      --image REF   image reference override for a new sandbox
      --publish HOST:GUEST[/tcp]
                    publish a guest TCP port on host loopback (repeatable)
      --allow-network CIDR[:PORT]
                    allow egress CIDR rule (repeatable; optional udp: prefix)
      --deny-network CIDR[:PORT]
                    deny egress CIDR rule (repeatable; optional udp: prefix)
      --policy-profile deny-all|balanced|sbx-compat
                    opt-in egress profile (default deny-all)
      --docker      run the dedicated Docker profile (privileged cgroup/network caps)
      --cpus N      CPUs for a new sandbox (0 selects the daemon default)
  -m, --memory SIZE memory limit for a new sandbox such as 512m or 2g
  -e, --env KEY=VALUE
                    environment override for the agent session (repeatable)
      --env-file FILE
                    read environment overrides from a file (repeatable)
      --rm          remove the sandbox after the agent session exits
  -h, --help        help for run
`

	shellAgent        = "shell"
	shellPath         = "/bin/sh"
	helpCommand       = "help"
	helpFlag          = "--help"
	helpShort         = "-h"
	detachFlag        = "--detach"
	detachShort       = "-d"
	nameFlag          = "--name"
	imageFlag         = "--image"
	publishFlag       = "--publish"
	policyProfileFlag = "--policy-profile"
	privilegedFlag    = "--privileged"
	dockerFlag        = "--docker"
	allowFlag         = "--allow-network"
	denyFlag          = "--deny-network"
	cpusFlag          = "--cpus"
	memoryFlag        = "--memory"
	memoryShort       = "-m"
	envFlag           = "--env"
	envShort          = "-e"
	envFileFlag       = "--env-file"
	removeFlag        = "--rm"
)

var errRunAgentRequired = errors.New("agent is required when --name is not set")

type runResources struct {
	cpus    uint32
	memory  uint32
	env     []string
	profile string
	ports   []sdk.Port
	allow   []sdk.NetworkRule
	deny    []sdk.NetworkRule
}

type runOptions struct {
	name       string
	image      string
	publish    []string
	allow      []string
	deny       []string
	profile    string
	privileged bool
	cpus       uint
	memory     string
	env        []string
	envFiles   []string
	detach     bool
	remove     bool
	help       bool
}

// run creates or reuses a sandbox, starts it, and attaches an agent session.
func (r *Runner) run(ctx context.Context, args []string) int {
	head, agentArgs := splitAgentArgs(args)
	opts, positionals, err := parseRunArgs(head)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "ksbx run: %v\n", err)
		_, _ = fmt.Fprint(r.Err, runUsage)
		return 2
	}
	if opts.help {
		_, _ = fmt.Fprint(r.Out, runUsage)
		return 0
	}
	agent, workspacePaths, workspacesExplicit, err := parseRunPositionals(positionals)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "ksbx run: %v\n", err)
		return 2
	}
	if err := validateRunRequest(opts, agent); err != nil {
		_, _ = fmt.Fprintf(r.Err, "ksbx run: %v\n", err)
		if errors.Is(err, errRunAgentRequired) {
			_, _ = fmt.Fprint(r.Err, runUsage)
		}
		return 2
	}
	applyAgentDefaults(agent, &opts.image, &opts.privileged)
	resources, err := prepareRunResources(opts)
	if err != nil {
		_, _ = fmt.Fprintf(r.Err, "ksbx run: %v\n", err)
		return 2
	}

	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()

	sandbox, created, workspaces, err := r.reuseOrCreateSandbox(ctx, client, opts, agent, workspacePaths, workspacesExplicit, resources)
	if err != nil {
		r.error(err)
		return 1
	}
	return r.runAttached(ctx, client, opts, sandbox, created, agent, workspaces, workspacesExplicit, agentArgs, resources)
}

func (r *Runner) runAttached(ctx context.Context, client sdk.Client, opts runOptions, sandbox *sdk.Sandbox, created bool, agent string, workspaces []sdk.Workspace, workspacesExplicit bool, agentArgs []string, resources runResources) int {
	if sandbox == nil || sandbox.ID == "" {
		r.error(errors.New("sandbox creation returned no sandbox"))
		return 1
	}
	if !created {
		if err := checkReusedRun(sandbox, workspaces, workspacesExplicit); err != nil {
			r.error(err)
			return 1
		}
		r.warnReusedResources(sandbox, opts, resources)
	}
	if err := ensureSandboxRunning(ctx, client, sandbox); err != nil {
		r.error(err)
		return 1
	}
	if opts.detach {
		_, _ = fmt.Fprintln(r.Out, sandbox.ID)
		return 0
	}
	if agent == "" {
		agent = shellAgent
	}
	interactive, tty := runTerminal(r.In)
	code := r.execSession(ctx, client, sandbox.ID, runArgv(agent, agentArgs), execOptions{env: resources.env}, interactive, tty)
	if opts.remove {
		if err := removeRunSandbox(ctx, client, sandbox); err != nil {
			r.error(err)
			return 1
		}
	}
	return code
}

func removeRunSandbox(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	op, err := client.Sandboxes().Delete(ctx, sandbox.ID, sdk.DeleteOptions{Force: true})
	if err != nil {
		return err
	}
	if op != nil && op.State == sdk.StateFailed {
		return fmt.Errorf("remove sandbox %s failed: %s", sandbox.Name, op.Error)
	}
	return nil
}

func prepareRunResources(opts runOptions) (runResources, error) {
	if opts.remove && opts.detach {
		return runResources{}, errors.New("--rm cannot be combined with --detach")
	}
	cpus, err := validateCPUs(opts.cpus)
	if err != nil {
		return runResources{}, err
	}
	memoryMiB, err := parseMemoryMiB(opts.memory)
	if err != nil {
		return runResources{}, err
	}
	ports, err := resolvePorts(opts.publish)
	if err != nil {
		return runResources{}, err
	}
	allow, err := resolveNetworkRules(opts.allow)
	if err != nil {
		return runResources{}, err
	}
	deny, err := resolveNetworkRules(opts.deny)
	if err != nil {
		return runResources{}, err
	}
	env, err := buildExecEnv(opts.env, opts.envFiles)
	if err != nil {
		return runResources{}, err
	}
	return runResources{cpus: cpus, memory: memoryMiB, env: env, profile: opts.profile, ports: ports, allow: allow, deny: deny}, nil
}

func (r *Runner) warnReusedResources(sandbox *sdk.Sandbox, opts runOptions, resources runResources) {
	if resources.cpus != 0 || resources.memory != 0 {
		_, _ = fmt.Fprintf(r.Err, "warning: sandbox %s keeps its existing CPU/memory; sizing flags apply only to new sandboxes\n", sandbox.Name)
	}
	if len(opts.publish) > 0 {
		_, _ = fmt.Fprintf(r.Err, "warning: sandbox %s keeps its existing published ports; --publish applies only to new sandboxes\n", sandbox.Name)
	}
	if len(opts.allow) > 0 || len(opts.deny) > 0 || opts.profile != "" {
		_, _ = fmt.Fprintf(r.Err, "warning: sandbox %s keeps its existing network policy; policy flags apply only to new sandboxes\n", sandbox.Name)
	}
}

func splitAgentArgs(args []string) ([]string, []string) {
	for i, arg := range args {
		if arg == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func parseRunArgs(args []string) (runOptions, []string, error) {
	var opts runOptions
	positionals := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		consumed, err := parseRunFlag(args, i, &opts)
		if err != nil {
			return opts, nil, err
		}
		if consumed == 0 {
			positionals = append(positionals, args[i])
			continue
		}
		i += consumed - 1
	}
	return opts, positionals, nil
}

func parseRunFlag(args []string, index int, opts *runOptions) (int, error) {
	arg := args[index]
	if consumed, handled, err := parseRunValueFlag(args, index, arg, opts); handled {
		return consumed, err
	}
	if consumed, handled, err := parseRunAssignmentFlag(arg, opts); handled {
		return consumed, err
	}
	if strings.HasPrefix(arg, "-") && arg != "-" {
		return 0, fmt.Errorf("unknown flag %q", arg)
	}
	return 0, nil
}

func parseRunValueFlag(args []string, index int, arg string, opts *runOptions) (int, bool, error) {
	switch arg {
	case helpShort, helpFlag:
		opts.help = true
		return 1, true, nil
	case detachShort, detachFlag:
		opts.detach = true
		return 1, true, nil
	case removeFlag:
		opts.remove = true
		return 1, true, nil
	case nameFlag:
		consumed, err := parseRunValue(args, index, nameFlag, &opts.name)
		return consumed, true, err
	case imageFlag:
		consumed, err := parseRunValue(args, index, imageFlag, &opts.image)
		return consumed, true, err
	case publishFlag:
		consumed, err := parseRunListValue(args, index, publishFlag, &opts.publish)
		return consumed, true, err
	case allowFlag:
		consumed, err := parseRunListValue(args, index, allowFlag, &opts.allow)
		return consumed, true, err
	case policyProfileFlag:
		consumed, err := parseRunValue(args, index, policyProfileFlag, &opts.profile)
		return consumed, true, err
	case denyFlag:
		consumed, err := parseRunListValue(args, index, denyFlag, &opts.deny)
		return consumed, true, err
	case cpusFlag:
		consumed, err := parseRunUintValue(args, index, cpusFlag, &opts.cpus)
		return consumed, true, err
	case memoryShort, memoryFlag:
		consumed, err := parseRunValue(args, index, memoryFlag, &opts.memory)
		return consumed, true, err
	case envShort, envFlag:
		consumed, err := parseRunListValue(args, index, envFlag, &opts.env)
		return consumed, true, err
	case envFileFlag:
		consumed, err := parseRunListValue(args, index, envFileFlag, &opts.envFiles)
		return consumed, true, err
	default:
		return 0, false, nil
	}
}

func parseRunAssignmentFlag(arg string, opts *runOptions) (int, bool, error) {
	if value, ok := strings.CutPrefix(arg, nameFlag+"="); ok {
		consumed, err := setRunValue(nameFlag, value, &opts.name)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, imageFlag+"="); ok {
		consumed, err := setRunValue(imageFlag, value, &opts.image)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, publishFlag+"="); ok {
		consumed, err := appendRunListValue(publishFlag, value, &opts.publish)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, allowFlag+"="); ok {
		consumed, err := appendRunListValue(allowFlag, value, &opts.allow)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, denyFlag+"="); ok {
		consumed, err := appendRunListValue(denyFlag, value, &opts.deny)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, cpusFlag+"="); ok {
		consumed, err := setRunUintValue(cpusFlag, value, &opts.cpus)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, memoryFlag+"="); ok {
		consumed, err := setRunValue(memoryFlag, value, &opts.memory)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, envFlag+"="); ok {
		consumed, err := appendRunListValue(envFlag, value, &opts.env)
		return consumed, true, err
	}
	if value, ok := strings.CutPrefix(arg, envFileFlag+"="); ok {
		consumed, err := appendRunListValue(envFileFlag, value, &opts.envFiles)
		return consumed, true, err
	}
	return 0, false, nil
}

func parseRunUintValue(args []string, index int, name string, target *uint) (int, error) {
	if index+1 >= len(args) {
		return 0, fmt.Errorf("%s requires a value", name)
	}
	if _, err := setRunUintValue(name, args[index+1], target); err != nil {
		return 0, err
	}
	return 2, nil
}

func setRunUintValue(name, value string, target *uint) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%s requires a non-negative integer", name)
	}
	*target = uint(parsed)
	return 1, nil
}

func parseRunListValue(args []string, index int, name string, target *[]string) (int, error) {
	if index+1 >= len(args) {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	if _, err := appendRunListValue(name, args[index+1], target); err != nil {
		return 0, err
	}
	return 2, nil
}

func appendRunListValue(name, value string, target *[]string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	*target = append(*target, value)
	return 1, nil
}

func parseRunValue(args []string, index int, name string, target *string) (int, error) {
	if index+1 >= len(args) {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	if _, err := setRunValue(name, args[index+1], target); err != nil {
		return 0, err
	}
	return 2, nil
}

func setRunValue(name, value string, target *string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("%s requires a non-empty value", name)
	}
	*target = value
	return 1, nil
}

func parseRunPositionals(positionals []string) (agent string, paths []string, explicit bool, err error) {
	if len(positionals) > 17 {
		return "", nil, false, errors.New("at most 16 workspaces are supported")
	}
	if len(positionals) == 0 {
		return "", nil, false, nil
	}
	agent = positionals[0]
	paths = positionals[1:]
	return agent, paths, len(paths) > 0, nil
}

func validateRunRequest(opts runOptions, agent string) error {
	if agent != "" {
		return validateRunAgent(agent)
	}
	if opts.name == "" {
		return errRunAgentRequired
	}
	return nil
}

func validateRunAgent(name string) error {
	return validateAgent(name)
}

func isAgentName(value string) bool {
	registry, err := agentRegistry()
	if err != nil {
		return false
	}
	_, ok := registry.Lookup(value)
	return ok
}

func runArgv(name string, agentArgs []string) []string {
	return append(agentCommandArgs(name), agentArgs...)
}

func runTerminal(input any) (interactive, tty bool) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, false
	}
	return true, true
}

func checkReusedRun(sandbox *sdk.Sandbox, requested []sdk.Workspace, explicit bool) error {
	if !explicit {
		return nil
	}
	return checkReusedWorkspace(sandbox, requested)
}

func checkReusedWorkspace(sandbox *sdk.Sandbox, requested []sdk.Workspace) error {
	if len(requested) == 0 {
		return nil
	}
	existing := sandbox.Workspaces
	if len(existing) == 0 && sandbox.Workspace != "" {
		existing = []sdk.Workspace{{Path: sandbox.Workspace}}
	}
	if len(existing) != len(requested) || strings.Join(workspacePaths(existing), "\x00") != strings.Join(workspacePaths(requested), "\x00") {
		return fmt.Errorf("sandbox %s already uses workspaces %v; refusing to ignore %v", sandbox.Name, workspacePaths(existing), workspacePaths(requested))
	}
	for i := range existing {
		if existing[i].ReadOnly != requested[i].ReadOnly {
			return fmt.Errorf("sandbox %s already uses workspace modes %v; refusing to ignore %v", sandbox.Name, existing, requested)
		}
	}
	return nil
}

func (r *Runner) reuseOrCreateSandbox(ctx context.Context, client sdk.Client, opts runOptions, agent string, paths []string, explicit bool, resources runResources) (*sdk.Sandbox, bool, []sdk.Workspace, error) {
	if opts.name != "" {
		existing, requested, found, err := r.findRunReuse(ctx, client, opts.name, paths, explicit)
		if err != nil {
			return nil, false, nil, err
		}
		if found {
			return existing, false, requested, nil
		}
	}
	workspaces, err := resolveWorkspaces(paths, true)
	if err != nil {
		return nil, false, nil, err
	}
	created, _, err := r.createRunSandbox(ctx, client, opts, agent, workspaces, resources)
	return created, true, workspaces, err
}

func (r *Runner) findRunReuse(ctx context.Context, client sdk.Client, name string, paths []string, explicit bool) (*sdk.Sandbox, []sdk.Workspace, bool, error) {
	existing, found, err := lookupSandboxByName(ctx, client, name)
	if err != nil {
		return nil, nil, false, err
	}
	if !found {
		return nil, nil, false, nil
	}
	if !explicit {
		return existing, nil, true, nil
	}
	requested, err := resolveWorkspaces(paths, false)
	if err != nil {
		return nil, nil, false, err
	}
	return existing, requested, true, nil
}

func (r *Runner) createRunSandbox(ctx context.Context, client sdk.Client, opts runOptions, agent string, workspaces []sdk.Workspace, resources runResources) (*sdk.Sandbox, bool, error) {
	name, err := runSandboxName(ctx, client, opts.name, agent)
	if err != nil {
		return nil, false, err
	}
	workspace := ""
	if len(workspaces) > 0 {
		workspace = workspaces[0].Path
	}
	op, err := client.Sandboxes().Create(ctx, sdk.CreateRequest{
		Name:          name,
		Image:         opts.image,
		Workspace:     workspace,
		Workspaces:    workspaces,
		Ports:         resources.ports,
		Allow:         resources.allow,
		Deny:          resources.deny,
		Agent:         agent,
		Detached:      opts.detach,
		CPUs:          resources.cpus,
		MemoryMiB:     resources.memory,
		PolicyProfile: resources.profile,
		Privileged:    opts.privileged,
		Env:           envMap(resources.env),
	})
	if err != nil {
		return r.recoverRunCreate(ctx, client, opts.name, err)
	}
	if op == nil || op.SandboxID == "" {
		created, found, err := lookupSandboxByName(ctx, client, name)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, errors.New("sandbox creation returned no sandbox ID")
		}
		return created, true, nil
	}
	created, err := client.Sandboxes().Get(ctx, op.SandboxID)
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

func (r *Runner) recoverRunCreate(ctx context.Context, client sdk.Client, name string, createErr error) (*sdk.Sandbox, bool, error) {
	if name != "" {
		// A concurrent creator may have won the name; reuse only a sandbox
		// that the daemon now reports for the requested name.
		if existing, found, lookupErr := lookupSandboxByName(ctx, client, name); lookupErr == nil && found {
			return existing, false, nil
		}
	}
	return nil, false, createErr
}

func ensureSandboxRunning(ctx context.Context, client sdk.Client, sandbox *sdk.Sandbox) error {
	switch sandbox.State {
	case sdk.StateRunning:
		return nil
	case sdk.StateStopped:
		op, err := client.Sandboxes().Start(ctx, sandbox.ID)
		if err != nil {
			return err
		}
		if op != nil && op.State == sdk.StateFailed {
			return fmt.Errorf("start sandbox %s failed: %s", sandbox.Name, op.Error)
		}
		return nil
	default:
		return fmt.Errorf("sandbox %s is %s; cannot attach", sandbox.Name, sandbox.State)
	}
}

func lookupSandboxByName(ctx context.Context, client sdk.Client, name string) (*sdk.Sandbox, bool, error) {
	seen := make(map[string]struct{})
	token := ""
	for pages := 0; pages < 10000; pages++ {
		page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: 100, PageToken: token})
		if err != nil {
			return nil, false, err
		}
		for i := range page.Items {
			item := &page.Items[i]
			if item.Name == name || item.ID == name {
				return item, true, nil
			}
		}
		if page.NextPageToken == "" {
			return nil, false, nil
		}
		if _, exists := seen[page.NextPageToken]; exists {
			return nil, false, errors.New("invalid sandbox pagination")
		}
		seen[page.NextPageToken] = struct{}{}
		token = page.NextPageToken
	}
	return nil, false, errors.New("too many sandbox pages")
}

func runSandboxName(ctx context.Context, client sdk.Client, requested, agent string) (string, error) {
	if requested != "" {
		if !validRunName(requested) {
			return "", fmt.Errorf("invalid sandbox name %q", requested)
		}
		return requested, nil
	}
	return newRunName(ctx, client, agent)
}

func newRunName(ctx context.Context, client sdk.Client, agent string) (string, error) {
	prefix := agent
	if prefix == "" {
		prefix = "sandbox"
	}
	for attempt := 0; attempt < 5; attempt++ {
		var nonce [4]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", fmt.Errorf("generate sandbox name: %w", err)
		}
		name := prefix + "-" + hex.EncodeToString(nonce[:])
		_, found, err := lookupSandboxByName(ctx, client, name)
		if err != nil {
			return "", err
		}
		if !found {
			return name, nil
		}
	}
	return "", errors.New("could not allocate a unique sandbox name")
}

func validRunName(name string) bool {
	if name == "" || len(name) > 63 || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}
