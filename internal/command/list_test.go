package command

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type twoSandbox struct{ fakeSandbox }

func (twoSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{
		{
			ID: "sb-1", Name: "one", State: sdk.StateRunning, Image: "alpine", Agent: "shell", Detached: true,
			LastUsedAt: time.Date(2026, 10, 31, 1, 2, 5, 0, time.UTC),
			Workspace:  "/workspace", Generation: 2,
			Ports:     []sdk.Port{{Host: 8080, Guest: 3000, Protocol: "tcp"}},
			CreatedAt: time.Date(2026, 10, 31, 1, 2, 3, 4, time.UTC),
			UpdatedAt: time.Date(2026, 10, 31, 1, 2, 4, 0, time.UTC),
		},
		{ID: "sb-2", Name: "two", State: sdk.StateStopped},
	}}, nil
}

func listRunner(sandbox sdk.SandboxService) (*Runner, *bytes.Buffer) {
	var out bytes.Buffer
	return &Runner{
		Out: &out, Err: &out, Socket: "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil },
	}, &out
}

func TestListJSONMatchesDocumentedFields(t *testing.T) {
	runner, out := listRunner(twoSandbox{})
	if code := runner.Run(context.Background(), []string{"ls", "--format", "json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var items []sandboxOutput
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if len(items) != 2 || items[0].Name != "one" || items[0].Status != sdk.StateRunning ||
		len(items[0].Workspaces) != 1 || items[0].Workspaces[0] != "/workspace" ||
		len(items[0].Ports) != 1 || items[0].Ports[0].HostPort != 8080 ||
		items[0].Agent != "shell" || !items[0].Detached ||
		items[0].LastUsedAt != "2026-10-31T01:02:05Z" ||
		items[0].CreatedAt != "2026-10-31T01:02:03.000000004Z" {
		t.Fatalf("unexpected JSON items: %#v", items)
	}
	if items[1].Workspaces == nil || len(items[1].Workspaces) != 0 {
		t.Fatalf("mountless workspaces must be an empty array: %#v", items[1].Workspaces)
	}
}

func TestListQuietAndYAML(t *testing.T) {
	runner, out := listRunner(twoSandbox{})
	if code := runner.Run(context.Background(), []string{"ls", "-q"}); code != 0 {
		t.Fatalf("quiet exit=%d output=%q", code, out.String())
	}
	if out.String() != "one\ntwo\n" {
		t.Fatalf("quiet output=%q", out.String())
	}

	runner, out = listRunner(twoSandbox{})
	if code := runner.Run(context.Background(), []string{"ls", "--format", "yaml"}); code != 0 {
		t.Fatalf("yaml exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "- name: one") || !strings.Contains(out.String(), "workspaces:") {
		t.Fatalf("unexpected YAML: %q", out.String())
	}
}

func TestListRejectsInvalidFormatAndQuietCombination(t *testing.T) {
	for _, args := range [][]string{
		{"ls", "--format", "xml"},
		{"ls", "--quiet", "--json"},
		{"ls", "--limit", "0"},
	} {
		called := false
		runner := &Runner{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, NewClient: func(string) (sdk.Client, error) {
			called = true
			return fakeClient{}, nil
		}}
		if code := runner.Run(context.Background(), args); code != 2 || called {
			t.Fatalf("%v: exit=%d client-called=%t", args, code, called)
		}
	}
}

func TestListEmptyJSONIsArray(t *testing.T) {
	runner, out := listRunner(emptySandbox{})
	if code := runner.Run(context.Background(), []string{"ls", "--json"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.TrimSpace(out.String()) != "[]" {
		t.Fatalf("empty JSON=%q", out.String())
	}
}

type emptySandbox struct{ fakeSandbox }

func (emptySandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{}, nil
}

func TestListHelpExitsZero(t *testing.T) {
	runner, out := listRunner(twoSandbox{})
	if code := runner.Run(context.Background(), []string{"ls", "--help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(out.String(), "usage: ksbx ls") {
		t.Fatalf("missing help: %q", out.String())
	}
}
