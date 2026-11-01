package kit

import (
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
		"apiVersion: klorq.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, workspace: {seed: https://example.com/repo}}\n",
		"apiVersion: klorq.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, mcp: {allow: [github]}}\n",
		"apiVersion: klorq.dev/v1alpha1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex, unknown: true}\n",
		"apiVersion: v1\nkind: Kit\nmetadata: {name: x}\nspec: {agent: codex}\n",
	} {
		if _, err := Decode(strings.NewReader(body)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
}
