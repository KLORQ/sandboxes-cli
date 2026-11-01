package kit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeLocalKit(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: klorq.dev/v1alpha1
kind: Kit
metadata: {name: codex-go}
spec:
  agent: codex
  policy_profile: sbx-compat
  mounts:
    - {path: /work, read_only: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Name != "codex-go" || doc.Spec.Agent != "codex" || len(doc.Paths()) != 1 || doc.Paths()[0] != "/work:ro" {
		t.Fatalf("doc=%+v paths=%v", doc, doc.Paths())
	}
}

func TestDecodeRejectsUnsupportedAndUnknown(t *testing.T) {
	for _, body := range []string{
		"apiVersion: klorq.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, mcp: {allow: [github]}}\n",
		"apiVersion: klorq.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, unknown: true}\n",
		"apiVersion: v1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex}\n",
	} {
		if _, err := Decode(strings.NewReader(body)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
}

func TestSeedValidation(t *testing.T) {
	for _, seed := range []string{
		"https://github.com/example/repo.git",
		"ssh://git@example.com/repo.git",
		"git@example.com:repo.git",
	} {
		if err := validateSeed(seed); err != nil {
			t.Fatalf("rejected %q: %v", seed, err)
		}
	}
	for _, seed := range []string{
		"file:///tmp/repo", "-u", "repo", "https://example.com/a b", "git@example.com",
	} {
		if err := validateSeed(seed); err == nil {
			t.Fatalf("accepted %q", seed)
		}
	}
}

func TestDecodeSeedKit(t *testing.T) {
	doc, err := Decode(strings.NewReader(`apiVersion: klorq.dev/v1alpha1
kind: Kit
metadata: {name: seeded}
spec:
  agent: codex
  workspace: {seed: "https://github.com/example/repo.git"}
`))
	if err != nil || doc.Spec.Workspace.Seed == "" {
		t.Fatalf("doc=%+v err=%v", doc, err)
	}
}

func TestResolveSeedUsesExistingCache(t *testing.T) {
	seed := "https://github.com/example/repo.git"
	sum := sha256.Sum256([]byte(seed))
	cache := t.TempDir()
	dest := filepath.Join(cache, hex.EncodeToString(sum[:12]))
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSeed(context.Background(), seed, cache)
	if err != nil || got != dest {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
