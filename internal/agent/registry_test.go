package agent

import (
	"strings"
	"testing"
)

func TestRegistry(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	kimi, ok := r.Lookup("kimi")
	if !ok || !kimi.Launchable() || !strings.HasPrefix(kimi.Image, "ghcr.io/klorq/sandbox-kimi@sha256:") || kimi.Command[0] != "kimi" {
		t.Fatalf("kimi=%+v ok=%v", kimi, ok)
	}
	if claude, ok := r.Lookup("claude"); !ok || claude.Launchable() {
		t.Fatalf("claude=%+v ok=%v", claude, ok)
	}
	if _, ok := r.Lookup("missing"); ok {
		t.Fatal("missing agent found")
	}
	if len(r.Names()) < 10 {
		t.Fatalf("names=%v", r.Names())
	}
}
