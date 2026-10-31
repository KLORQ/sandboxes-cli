package command

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type pruneOptions struct {
	dryRun bool
	force  bool
	format string
	until  *time.Time
}

func (r *Runner) prune(ctx context.Context, args []string) int {
	opts, help, err := parsePruneOptions(args)
	if help {
		_, _ = fmt.Fprint(r.Out, pruneUsage)
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
	items, err := collectSandboxes(ctx, client, 200)
	if err != nil {
		r.error(err)
		return 1
	}
	stopped := filterStopped(items, opts.until)
	if len(stopped) == 0 {
		if opts.format == listFormatTable {
			_, _ = fmt.Fprintln(r.Out, "No stopped sandboxes")
			return 0
		}
		return pruneRender(r, opts.format, nil, nil)
	}
	if opts.dryRun {
		if opts.format == listFormatTable {
			printPruneCandidates(r.Out, stopped)
			return 0
		}
		return pruneRender(r, opts.format, nil, stopped)
	}
	if !opts.force {
		confirmed, err := r.confirmPrune(len(stopped))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Prune canceled")
			return 0
		}
	}
	operations, failures := r.deletePrunedSandboxes(ctx, client, stopped)
	if code := pruneRender(r, opts.format, operations, nil); code != 0 {
		return code
	}
	if failures != nil {
		r.error(failures)
		return 1
	}
	return 0
}

func parsePruneOptions(args []string) (pruneOptions, bool, error) {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "list stopped sandboxes without removing them")
	force := fs.Bool("force", false, "remove without confirmation")
	fs.BoolVar(force, "f", false, "remove without confirmation")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	filter := fs.String("filter", "", "until=TIMESTAMP or until=DURATION")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return pruneOptions{}, true, nil
		}
		return pruneOptions{}, false, err
	}
	if fs.NArg() != 0 {
		return pruneOptions{}, false, errors.New("usage: ksbx prune [--dry-run] [-f|--force] [--format table|json|yaml]")
	}
	selected, err := resolveOperationFormat(*format, *jsonOutput)
	if err != nil {
		return pruneOptions{}, false, err
	}
	until, hasUntil, err := parsePruneFilter(*filter, time.Now())
	if err != nil {
		return pruneOptions{}, false, err
	}
	var untilPtr *time.Time
	if hasUntil {
		untilPtr = &until
	}
	return pruneOptions{dryRun: *dryRun, force: *force, format: selected, until: untilPtr}, false, nil
}

func pruneRender(r *Runner, format string, operations []*sdk.Operation, sandboxes []sdk.Sandbox) int {
	var err error
	if sandboxes != nil {
		err = renderSandboxes(r.Out, format, sandboxes)
	} else {
		err = renderOperations(r.Out, format, operations)
	}
	if err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func filterStopped(items []sdk.Sandbox, until *time.Time) []sdk.Sandbox {
	stopped := make([]sdk.Sandbox, 0, len(items))
	for i := range items {
		if items[i].State != sdk.StateStopped {
			continue
		}
		if until != nil && (items[i].StoppedAt.IsZero() || !items[i].StoppedAt.Before(*until)) {
			continue
		}
		stopped = append(stopped, items[i])
	}
	return stopped
}

func parsePruneFilter(value string, now time.Time) (time.Time, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false, nil
	}
	if !strings.HasPrefix(value, "until=") {
		return time.Time{}, false, errors.New("prune filter must be until=TIMESTAMP or until=DURATION")
	}
	value = strings.TrimPrefix(value, "until=")
	if value == "" {
		return time.Time{}, false, errors.New("prune filter value is empty")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, true, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), true, nil
	}
	if duration, err := time.ParseDuration(value); err == nil && duration >= 0 {
		return now.Add(-duration), true, nil
	}
	return time.Time{}, false, errors.New("prune filter must be an RFC3339 timestamp, Unix seconds, or a non-negative duration")
}

func (r *Runner) deletePrunedSandboxes(ctx context.Context, client sdk.Client, stopped []sdk.Sandbox) ([]*sdk.Operation, error) {
	var failures []error
	operations := make([]*sdk.Operation, 0, len(stopped))
	for i := range stopped {
		op, err := client.Sandboxes().Delete(ctx, stopped[i].ID, sdk.DeleteOptions{Force: true})
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if op != nil && op.State == sdk.StateFailed {
			failures = append(failures, fmt.Errorf("prune sandbox %s failed: %s", stopped[i].Name, op.Error))
			continue
		}
		operations = append(operations, op)
	}
	return operations, errors.Join(failures...)
}

func printPruneCandidates(out io.Writer, items []sdk.Sandbox) {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tSTATE")
	for i := range items {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", items[i].ID, items[i].Name, items[i].State)
	}
	_ = tw.Flush()
}

func (r *Runner) confirmPrune(count int) (bool, error) {
	file, ok := r.In.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return false, errors.New("prune confirmation requires a terminal; use --force to skip confirmation")
	}
	if _, err := fmt.Fprintf(r.Err, "Remove %d stopped sandbox(es)? [y/N] ", count); err != nil {
		return false, fmt.Errorf("write prune prompt: %w", err)
	}
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read prune confirmation: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == answerShortYes || answer == answerYes, nil
}
