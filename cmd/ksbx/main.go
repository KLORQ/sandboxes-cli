package main

import (
	"os"

	"github.com/KLORQ/sandboxes-cli/internal/command"
)

func main() {
	ctx, stop := signalContext()
	code := command.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
