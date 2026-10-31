//go:build !windows

package command

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
	"golang.org/x/term"
)

func watchTerminalResize(ctx context.Context, file *os.File, session sdk.ExecSession) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				cols, rows, err := term.GetSize(int(file.Fd()))
				if err == nil && cols > 0 && rows > 0 {
					size, sizeErr := terminalSize(rows, cols)
					if sizeErr != nil || session.Resize(size) != nil {
						return
					}
				}
			}
		}
	}()
	return func() { signal.Stop(signals) }
}
