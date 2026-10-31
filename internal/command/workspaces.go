package command

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func parseWorkspaceSpec(value string) (sdk.Workspace, error) {
	readOnly := strings.HasSuffix(value, ":ro")
	path := strings.TrimSuffix(value, ":ro")
	if path == "" || strings.ContainsRune(path, '\x00') {
		return sdk.Workspace{}, errors.New("workspace path is invalid")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return sdk.Workspace{}, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return sdk.Workspace{}, fmt.Errorf("workspace %s: %w", path, err)
	}
	if !info.IsDir() {
		return sdk.Workspace{}, fmt.Errorf("workspace %s is not a directory", path)
	}
	return sdk.Workspace{Path: absolute, ReadOnly: readOnly}, nil
}

func resolveWorkspaces(paths []string, defaultCurrent bool) ([]sdk.Workspace, error) {
	if len(paths) == 0 {
		if !defaultCurrent {
			return nil, nil
		}
		paths = []string{"."}
	}
	if len(paths) > 16 {
		return nil, errors.New("at most 16 workspaces are supported")
	}
	seen := make(map[string]struct{}, len(paths))
	workspaces := make([]sdk.Workspace, 0, len(paths))
	for _, path := range paths {
		workspace, err := parseWorkspaceSpec(path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[workspace.Path]; exists {
			return nil, fmt.Errorf("duplicate workspace %s", workspace.Path)
		}
		seen[workspace.Path] = struct{}{}
		workspaces = append(workspaces, workspace)
	}
	return workspaces, nil
}

func workspacePaths(workspaces []sdk.Workspace) []string {
	out := make([]string, 0, len(workspaces))
	for i := range workspaces {
		out = append(out, workspaces[i].Path)
	}
	return out
}
