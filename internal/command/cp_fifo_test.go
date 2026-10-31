//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package command

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRootedCopyRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("fifo", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, name := range []string{"fifo", "link"} {
		done := make(chan error, 1)
		go func() { done <- writeRootedCopyTar(io.Discard, root, name, "source", true) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s accepted", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("opening %s blocked", name)
		}
	}
}
