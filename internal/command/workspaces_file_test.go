package command

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceFileRequiresReadOnly(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "hold.txt")
	if err := os.WriteFile(file, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := parseWorkspaceSpec(file + ":ro")
	if err != nil {
		t.Fatalf("read-only file rejected: %v", err)
	}
	if !workspace.ReadOnly || workspace.Path != file {
		t.Fatalf("workspace=%+v", workspace)
	}
	for _, spec := range []string{file, file + ":rw"} {
		if _, err := parseWorkspaceSpec(spec); err == nil {
			t.Fatalf("writable file workspace accepted: %s", spec)
		}
	}
	if _, err := parseWorkspaceSpec(dir); err != nil {
		t.Fatalf("directory rejected: %v", err)
	}
}
