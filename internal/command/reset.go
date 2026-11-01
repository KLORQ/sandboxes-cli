package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

const resetUsage = `Usage: ksbx reset [--force] [--format table|json|yaml]

Remove every sandbox owned by the connected daemon. Settings, images and the
daemon state directory are not deleted. --force skips confirmation.
`

// reset removes all sandboxes. It intentionally does not delete daemon state,
// settings, images or unrelated host resources.
//
//nolint:gocognit,gocyclo,cyclop,funlen // reset combines confirmation and the same delete path as rm.
func (r *Runner) reset(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force", false, "remove all sandboxes without confirmation")
	fs.BoolVar(force, "f", false, "remove all sandboxes without confirmation")
	format := fs.String("format", listFormatTable, "output format: table, json or yaml")
	jsonOutput := fs.Bool("json", false, "output in JSON format")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = fmt.Fprint(r.Out, resetUsage)
			return 0
		}
		return r.flagParseFailure("reset", err)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprint(r.Err, resetUsage)
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
	targets, err := allSandboxIDs(ctx, client)
	if err != nil {
		r.error(err)
		return 1
	}
	if len(targets) == 0 {
		if selected != listFormatTable {
			if err := renderOperations(r.Out, selected, nil); err != nil {
				r.error(err)
				return 1
			}
			return 0
		}
		_, _ = fmt.Fprintln(r.Out, "No sandboxes to reset")
		return 0
	}
	if !*force {
		confirmed, err := r.confirmReset(len(targets))
		if err != nil {
			r.error(err)
			return 1
		}
		if !confirmed {
			_, _ = fmt.Fprintln(r.Out, "Reset canceled")
			return 0
		}
	}
	operations, removed, failed := r.deleteSandboxes(ctx, client, targets)
	if selected != listFormatTable {
		if err := renderOperations(r.Out, selected, operations); err != nil {
			r.error(err)
			return 1
		}
	} else {
		for _, name := range removed {
			_, _ = fmt.Fprintf(r.Out, "Removed sandbox %s\n", name)
		}
		_, _ = fmt.Fprintf(r.Out, "Reset %d sandbox(es)\n", len(removed))
	}
	if failed {
		return 1
	}
	return 0
}

func (r *Runner) confirmReset(count int) (bool, error) {
	if _, err := fmt.Fprintf(r.Err, "Remove all %d sandbox(es)? Settings and images are kept. [y/N] ", count); err != nil {
		return false, err
	}
	var answer string
	if _, err := fmt.Fscanln(r.In, &answer); err != nil {
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == answerShortYes || answer == answerYes, nil
}
