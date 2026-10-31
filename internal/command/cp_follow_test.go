package command

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func tarEntries(t *testing.T, data []byte) map[string]string {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	out := make(map[string]string)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[header.Name] = string(content)
	}
}

func TestWriteCopyTarFollowNestedLinks(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	source := filepath.Join(workspace, "src")
	sub := filepath.Join(source, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "sub.txt"), []byte("sub"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("inside.txt", filepath.Join(source, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(source, "dirlink")); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := writeCopyTarFollow(&buffer, source, "src", []sdk.Workspace{{Path: workspace}}); err != nil {
		t.Fatal(err)
	}
	entries := tarEntries(t, buffer.Bytes())
	if entries["src/link.txt"] != "inside" || entries["src/dirlink/sub.txt"] != "sub" {
		t.Fatalf("entries=%v", entries)
	}
}

func TestWriteCopyTarFollowRejectsEscapeAndCycle(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	source := filepath.Join(workspace, "src")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := writeCopyTarFollow(io.Discard, source, "src", []sdk.Workspace{{Path: workspace}}); err == nil {
		t.Fatal("nested escape accepted")
	}
	cycle := filepath.Join(workspace, "cycle")
	if err := os.MkdirAll(cycle, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(cycle, "self")); err != nil {
		t.Fatal(err)
	}
	if err := writeCopyTarFollow(io.Discard, cycle, "cycle", []sdk.Workspace{{Path: workspace}}); err == nil {
		t.Fatal("cycle accepted")
	}
}
