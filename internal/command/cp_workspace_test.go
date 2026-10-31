package command

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestFollowLinkWorkspaceBoundary(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	insideFile := filepath.Join(workspace, "inside.txt")
	outsideFile := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(insideFile, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(workspace, "inside-link")
	outsideLink := filepath.Join(workspace, "outside-link")
	if err := os.Symlink(insideFile, insideLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, outsideLink); err != nil {
		t.Fatal(err)
	}
	workspaces := []sdk.Workspace{{Path: workspace}}
	if err := ensureFollowInsideWorkspace(insideLink, insideFile, workspaces); err != nil {
		t.Fatalf("inside link rejected: %v", err)
	}
	if err := ensureFollowInsideWorkspace(outsideLink, outsideFile, workspaces); err == nil {
		t.Fatal("outside link accepted")
	}
	// A source outside every workspace is not constrained.
	if err := ensureFollowInsideWorkspace(outsideFile, outsideFile, workspaces); err != nil {
		t.Fatalf("outside source rejected: %v", err)
	}
	// A workspace reached through a symlink is resolved before containment.
	workspaceLink := filepath.Join(root, "workspace-link")
	if err := os.Symlink(workspace, workspaceLink); err != nil {
		t.Fatal(err)
	}
	linkedSource := filepath.Join(workspaceLink, "outside-link")
	if err := ensureFollowInsideWorkspace(linkedSource, outsideFile, []sdk.Workspace{{Path: workspaceLink}}); err == nil {
		t.Fatal("link through symlinked workspace accepted")
	}
	if !pathWithin(workspace, insideFile) || pathWithin(workspace, outsideFile) {
		t.Fatal("pathWithin containment is wrong")
	}
}

func TestRootedCopyConcurrentDirectoryReplacement(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	for dir, content := range map[string]string{filepath.Join(workspace, "inside"): "safe", outside: "SECRET-OUTSIDE"} {
		if err := os.WriteFile(filepath.Join(dir, "file"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(workspace, "link")
	if err := os.Symlink("inside", link); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(link)
			_ = os.Symlink(outside, link)
			_ = os.Remove(link)
			_ = os.Symlink("inside", link)
		}
	})
	for range 500 {
		var output bytes.Buffer
		_ = writeRootedCopyTar(&output, root, "link/file", "file", true)
		if bytes.Contains(output.Bytes(), []byte("SECRET-OUTSIDE")) {
			close(stop)
			wg.Wait()
			t.Fatal("outside data escaped into archive")
		}
	}
	close(stop)
	wg.Wait()
}

func TestRootedCopyEnforcesWorkspaceBoundary(t *testing.T) {
	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "safe"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var output bytes.Buffer
	if err := writeRootedCopyTar(&output, root, "safe", "safe", true); err != nil {
		t.Fatal(err)
	}
	if got := tarEntries(t, output.Bytes())["safe"]; got != "safe" {
		t.Fatalf("safe content = %q", got)
	}
	if err := writeRootedCopyTar(io.Discard, root, "escape", "escape", true); err == nil {
		t.Fatal("accepted link outside workspace")
	}
}
