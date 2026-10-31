package command

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestHelpDoesNotReturnEmptyUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"create", "--help"},
		{"create", "-h"},
		{"prune", "--help"},
		{"rm", "--help"},
		{"completion", "--help"},
	} {
		var out bytes.Buffer
		runner := &Runner{Out: &out, Err: &out, In: strings.NewReader("")}
		if code := runner.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v exit=%d output=%q", args, code, out.String())
		}
		if strings.TrimSpace(out.String()) == "" {
			t.Fatalf("%v produced empty help", args)
		}
		if !strings.Contains(out.String(), "usage:") {
			t.Fatalf("%v output=%q", args, out.String())
		}
	}
}

func TestRootHelpListsCommandsAndSocket(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out}
	if code := runner.Run(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	for _, want := range []string{"commands:", "run", "create", "--socket"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("help missing %q: %q", want, out.String())
		}
	}
}
