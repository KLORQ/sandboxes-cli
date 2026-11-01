package command

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type secretListClient struct {
	fakeClient
	items []sdk.RegistryCredentialSummary
}

func (s secretListClient) ListRegistryCredentials(context.Context) ([]sdk.RegistryCredentialSummary, error) {
	return s.items, nil
}

func TestSecretList(t *testing.T) {
	client := secretListClient{items: []sdk.RegistryCredentialSummary{
		{Registry: "ghcr.io", Username: "alice", Scope: "sandbox", SandboxName: "dev"},
	}}
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return client, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "ls"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("ghcr.io")) || bytes.Contains(out.Bytes(), []byte("password")) {
		t.Fatalf("output=%q", out.String())
	}
	out.Reset()
	if code := runner.Run(context.Background(), []string{"secret", "ls", "--json"}); code != 0 {
		t.Fatalf("json exit=%d", code)
	}
	var items []serviceSecretOutput
	if err := json.Unmarshal(out.Bytes(), &items); err != nil || len(items) != 1 || items[0].Username != "alice" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
}

func TestSecretListEmpty(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{Out: &out, Err: &out, NewClient: func(string) (sdk.Client, error) { return secretListClient{}, nil }}
	if code := runner.Run(context.Background(), []string{"secret", "ls"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("No secrets stored")) {
		t.Fatalf("output=%q", out.String())
	}
}
