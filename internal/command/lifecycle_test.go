package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

type lifecycleSandbox struct {
	fakeSandbox
	items     []sdk.Sandbox
	starts    []string
	stops     []string
	deletes   []string
	deleteErr error
}

func (s *lifecycleSandbox) List(context.Context, sdk.ListOptions) (*sdk.Page[sdk.Sandbox], error) {
	return &sdk.Page[sdk.Sandbox]{Items: s.items}, nil
}
func (s *lifecycleSandbox) Get(_ context.Context, id string) (*sdk.Sandbox, error) {
	for i := range s.items {
		if s.items[i].ID == id || s.items[i].Name == id {
			item := s.items[i]
			return &item, nil
		}
	}
	return nil, errors.New("not found")
}

func (s *lifecycleSandbox) Start(_ context.Context, id string) (*sdk.Operation, error) {
	s.starts = append(s.starts, id)
	return &sdk.Operation{ID: "op-start", State: sdk.StateDone}, nil
}
func (s *lifecycleSandbox) Stop(_ context.Context, id string, _ sdk.StopOptions) (*sdk.Operation, error) {
	s.stops = append(s.stops, id)
	return &sdk.Operation{ID: "op-stop", State: sdk.StateDone}, nil
}
func (s *lifecycleSandbox) Delete(_ context.Context, id string, _ sdk.DeleteOptions) (*sdk.Operation, error) {
	s.deletes = append(s.deletes, id)
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	return &sdk.Operation{ID: "op-delete", State: sdk.StateDone}, nil
}

func lifecycleRunner(sandbox *lifecycleSandbox) (*Runner, *bytes.Buffer) {
	var out bytes.Buffer
	return &Runner{
		Out: &out, Err: &out, In: strings.NewReader(""),
		NewClient: func(string) (sdk.Client, error) { return fakeClient{sandbox: sandbox}, nil },
	}, &out
}

func TestRemoveRequiresForceWithoutTerminal(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "dev"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "dev"}); code != 1 || len(sandbox.deletes) != 0 {
		t.Fatalf("exit=%d deletes=%v output=%q", code, sandbox.deletes, out.String())
	}
	if !strings.Contains(out.String(), "use --force") {
		t.Fatalf("missing force guidance: %q", out.String())
	}
}

func TestRemoveMultipleResolvesNamesAndForces(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "one"}, {ID: "sb-2", Name: "two"},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "-f", "one", "two"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-1,sb-2" {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
}

func TestRemovePartialFailureReturnsOne(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one"}}, deleteErr: errors.New("cannot remove")}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--force", "one", "missing"}); code != 1 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if len(sandbox.deletes) != 1 || !strings.Contains(out.String(), "cannot remove") || !strings.Contains(out.String(), "missing") {
		t.Fatalf("unexpected partial failure: deletes=%v output=%q", sandbox.deletes, out.String())
	}
}

func TestStopAndStartMultipleSandboxes(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-1", Name: "one"}, {ID: "sb-2", Name: "two"},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "one", "two"}); code != 0 {
		t.Fatalf("stop exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.stops, ",") != "sb-1,sb-2" {
		t.Fatalf("stops=%v", sandbox.stops)
	}
	if code := runner.Run(context.Background(), []string{"start", "one", "two"}); code != 0 {
		t.Fatalf("start exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.starts, ",") != "sb-1,sb-2" {
		t.Fatalf("starts=%v", sandbox.starts)
	}
}

func TestPruneDryRunListsOnlyStopped(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-run", Name: "running", State: sdk.StateRunning},
		{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "stopped") || strings.Contains(out.String(), "running") || len(sandbox.deletes) != 0 {
		t.Fatalf("unexpected dry-run: deletes=%v output=%q", sandbox.deletes, out.String())
	}
}

func TestPruneRemovesOnlyStopped(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{
		{ID: "sb-run", Name: "running", State: sdk.StateRunning},
		{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped},
	}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-stop" {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
}

func TestPruneRequiresForceWithoutTerminal(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune"}); code != 1 || len(sandbox.deletes) != 0 {
		t.Fatalf("exit=%d deletes=%v output=%q", code, sandbox.deletes, out.String())
	}
	if !strings.Contains(out.String(), "use --force") {
		t.Fatalf("missing force guidance: %q", out.String())
	}
}

func TestRemoveAllRequiresForceWithoutTerminal(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--all"}); code != 1 || len(sandbox.deletes) != 0 {
		t.Fatalf("exit=%d deletes=%v output=%q", code, sandbox.deletes, out.String())
	}
}

func TestRemoveAllForceDeletesEverySandbox(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one"}, {ID: "sb-2", Name: "two"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--all", "--force"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	if strings.Join(sandbox.deletes, ",") != "sb-1,sb-2" {
		t.Fatalf("deletes=%v", sandbox.deletes)
	}
}

func TestRemoveAllRejectsTargets(t *testing.T) {
	sandbox := &lifecycleSandbox{}
	runner, _ := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "--all", "one"}); code != 2 {
		t.Fatalf("exit=%d", code)
	}
}

func TestStopJSONAndYAMLFormats(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "--json", "one"}); code != 0 {
		t.Fatalf("json exit=%d output=%q", code, out.String())
	}
	var ops []operationOutput
	if err := json.Unmarshal(out.Bytes(), &ops); err != nil || len(ops) != 1 || ops[0].ID != "op-stop" {
		t.Fatalf("ops=%#v err=%v", ops, err)
	}
	runner, out = lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"stop", "--format", "yaml", "one"}); code != 0 {
		t.Fatalf("yaml exit=%d output=%q", code, out.String())
	}
	if !strings.Contains(out.String(), "id: op-stop") {
		t.Fatalf("unexpected yaml: %q", out.String())
	}
}

func TestRemoveJSONFormat(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-1", Name: "one"}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"rm", "-f", "--json", "one"}); code != 0 {
		t.Fatalf("exit=%d output=%q", code, out.String())
	}
	var ops []operationOutput
	if err := json.Unmarshal(out.Bytes(), &ops); err != nil || len(ops) != 1 || ops[0].ID != "op-delete" {
		t.Fatalf("ops=%#v err=%v", ops, err)
	}
}

func TestPruneJSONFormats(t *testing.T) {
	sandbox := &lifecycleSandbox{items: []sdk.Sandbox{{ID: "sb-stop", Name: "stopped", State: sdk.StateStopped}}}
	runner, out := lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "--dry-run", "--json"}); code != 0 {
		t.Fatalf("dry-run exit=%d output=%q", code, out.String())
	}
	var candidates []sandboxOutput
	if err := json.Unmarshal(out.Bytes(), &candidates); err != nil || len(candidates) != 1 || candidates[0].ID != "sb-stop" {
		t.Fatalf("candidates=%#v err=%v", candidates, err)
	}
	runner, out = lifecycleRunner(sandbox)
	if code := runner.Run(context.Background(), []string{"prune", "-f", "--json"}); code != 0 {
		t.Fatalf("force exit=%d output=%q", code, out.String())
	}
	var ops []operationOutput
	if err := json.Unmarshal(out.Bytes(), &ops); err != nil || len(ops) != 1 || ops[0].ID != "op-delete" {
		t.Fatalf("ops=%#v err=%v", ops, err)
	}
}

func TestParsePruneFilter(t *testing.T) {
	now := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Time
		has   bool
		ok    bool
	}{
		{"", time.Time{}, false, true},
		{"until=2026-10-31T01:00:00Z", time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC), true, true},
		{"until=1761862800", time.Unix(1761862800, 0).UTC(), true, true},
		{"until=2h", now.Add(-2 * time.Hour), true, true},
		{"until=bad", time.Time{}, false, false},
		{"not-until=2h", time.Time{}, false, false},
		{"until=-1h", time.Time{}, false, false},
	} {
		got, has, err := parsePruneFilter(tc.value, now)
		if (err == nil) != tc.ok || has != tc.has || !got.Equal(tc.want) {
			t.Fatalf("parsePruneFilter(%q)=%v,%t,%v", tc.value, got, has, err)
		}
	}
}

func TestFilterStoppedHonorsUntilAndUnknownStopTime(t *testing.T) {
	now := time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)
	items := []sdk.Sandbox{
		{ID: "old", State: sdk.StateStopped, StoppedAt: now.Add(-3 * time.Hour)},
		{ID: "new", State: sdk.StateStopped, StoppedAt: now.Add(-time.Hour)},
		{ID: "unknown", State: sdk.StateStopped},
		{ID: "running", State: sdk.StateRunning, StoppedAt: now.Add(-4 * time.Hour)},
	}
	cutoff := now.Add(-2 * time.Hour)
	got := filterStopped(items, &cutoff)
	if len(got) != 1 || got[0].ID != "old" {
		t.Fatalf("filtered=%v", got)
	}
	if all := filterStopped(items, nil); len(all) != 3 {
		t.Fatalf("unfiltered=%v", all)
	}
}
