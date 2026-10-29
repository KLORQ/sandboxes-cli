// Package command implements the CLI command tree.
package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	sdk "github.com/KLORQ/sandboxes-go-sdk"

	"github.com/KLORQ/sandboxes-cli/internal/version"
)

// Runner executes commands against a local daemon.
type Runner struct {
	Out       io.Writer
	Err       io.Writer
	Socket    string
	NewClient func(address string) (sdk.Client, error)
}

// NewRunner creates a CLI runner.
func NewRunner(out, errOut io.Writer) *Runner {
	return &Runner{
		Out:       out,
		Err:       errOut,
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
	global.SetOutput(r.Err)
	socket := global.String("socket", r.Socket, "daemon unix socket")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
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

	switch rest[0] {
	case "help", "-h", "--help":
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

func (r *Runner) create(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	image := fs.String("image", "", "image reference")
	workspace := fs.String("workspace", "", "host workspace path")
	idempotency := fs.String("idempotency-key", "", "idempotency key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx create [flags] <name>")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	op, err := client.Sandboxes().Create(ctx, sdk.CreateRequest{
		Name:           fs.Arg(0),
		Image:          *image,
		Workspace:      *workspace,
		IdempotencyKey: *idempotency,
	})
	if err != nil {
		r.error(err)
		return 1
	}
	r.printOperation(op)
	return 0
}

func (r *Runner) list(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	limit := fs.Int("limit", 50, "page size")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	page, err := client.Sandboxes().List(ctx, sdk.ListOptions{PageSize: *limit})
	if err != nil {
		r.error(err)
		return 1
	}
	tw := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tSTATE\tIMAGE\tWORKSPACE")
	for i := range page.Items {
		sb := &page.Items[i]
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", sb.ID, sb.Name, sb.State, sb.Image, sb.Workspace)
	}
	if err := tw.Flush(); err != nil {
		r.error(err)
		return 1
	}
	return 0
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
	sb, err := client.Sandboxes().Get(ctx, args[0])
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

func (r *Runner) remove(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	force := fs.Bool("force", false, "delete a running sandbox")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(r.Err, "usage: ksbx rm [--force] <id>")
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	op, err := client.Sandboxes().Delete(ctx, fs.Arg(0), sdk.DeleteOptions{Force: *force})
	if err != nil {
		r.error(err)
		return 1
	}
	r.printOperation(op)
	return 0
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
	return 0
}

func (r *Runner) lifecycle(ctx context.Context, name string, args []string) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(r.Err)
	grace := fs.Duration("grace", 0, "grace period")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintf(r.Err, "usage: ksbx %s [flags] <id>\n", name)
		return 2
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	var op *sdk.Operation
	if name == "start" {
		op, err = client.Sandboxes().Start(ctx, fs.Arg(0))
	} else {
		op, err = client.Sandboxes().Stop(ctx, fs.Arg(0), sdk.StopOptions{Grace: *grace})
	}
	if err != nil {
		r.error(err)
		return 1
	}
	r.printOperation(op)
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
	_, _ = fmt.Fprintf(r.Out, "id: %s\nname: %s\nstate: %s\nimage: %s\nworkspace: %s\ngeneration: %d\ncreated: %s\n",
		sb.ID, sb.Name, sb.State, sb.Image, sb.Workspace, sb.Generation, formatTime(sb.CreatedAt))
}

func (r *Runner) usage() {
	_, _ = fmt.Fprintln(r.Out, "usage: ksbx [--socket PATH] <command>")
	_, _ = fmt.Fprintln(r.Out, "commands: create, ls, get, start, stop, rm, wait, version, help")
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
