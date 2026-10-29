// Package command implements the CLI command tree.
package command

import (
	"context"
	"fmt"
	"io"

	"github.com/KLORQ/sandboxes-cli/internal/version"
)

// Run executes the command tree and returns a process exit code.
func Run(_ context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, _ = fmt.Fprintln(stdout, "usage: sandboxes <command>")
		_, _ = fmt.Fprintln(stdout, "commands: version, help")
		return 0
	}
	if args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, version.Version)
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
	return 2
}
