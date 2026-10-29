package command

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"version"}, &out, &out); code != 0 {
		t.Fatalf("exit code %d", code)
	}
	if out.Len() == 0 {
		t.Fatal("empty output")
	}
}

func TestUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"unknown"}, &out, &out); code != 2 {
		t.Fatalf("exit code %d", code)
	}
}

func TestCreateUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil },
	}
	if code := runner.Run(context.Background(), []string{"create", "dev"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "op-1") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestListUsesSDK(t *testing.T) {
	var out bytes.Buffer
	runner := &Runner{
		Out:       &out,
		Err:       &out,
		Socket:    "unused",
		NewClient: func(string) (sdk.Client, error) { return fakeClient{}, nil },
	}
	if code := runner.Run(context.Background(), []string{"ls"}); code != 0 {
		t.Fatalf("exit code %d, output %s", code, out.String())
	}
	if !strings.Contains(out.String(), "dev") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

type fakeClient struct{}

func (fakeClient) Sandboxes() sdk.SandboxService    { return fakeSandbox{} }
func (fakeClient) Operations() sdk.OperationService { return fakeOperations{} }
func (fakeClient) Close() error                     { return nil }

type fakeSandbox struct{}

func (fakeSandbox) Create(context.Context, sdk.CreateRequest) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", Kind: "create", State: "done"}, nil
}
func (fakeSandbox) Get(context.Context, string) (*sdk.Sandbox, error) {
	return &sdk.Sandbox{ID: "sb-1", Name: "dev", State: "stopped"}, nil
}
func (fakeSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: []sdk.Sandbox{{ID: "sb-1", Name: "dev", State: "stopped"}}}, nil
}
func (fakeSandbox) Start(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-2", Kind: "start", State: "done"}, nil
}
func (fakeSandbox) Stop(context.Context, string, sdk.StopOptions) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-3", Kind: "stop", State: "done"}, nil
}
func (fakeSandbox) Delete(context.Context, string, sdk.DeleteOptions) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-4", Kind: "delete", State: "done"}, nil
}
func (fakeSandbox) Watch(context.Context, sdk.WatchOptions) (sdk.EventStream, error) {
	return fakeEventStream{}, nil
}

type fakeEventStream struct{}

func (fakeEventStream) Recv() (*sdk.Event, error) { return nil, io.EOF }
func (fakeEventStream) Close() error              { return nil }

type fakeOperations struct{}

func (fakeOperations) Get(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: "done"}, nil
}
func (fakeOperations) Wait(context.Context, string) (*sdk.Operation, error) {
	return &sdk.Operation{ID: "op-1", State: "done"}, nil
}
