package command

import (
	"bytes"
	"context"
	"testing"
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
