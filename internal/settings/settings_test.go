package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "klorq", "settings.toml")
	want := Values{DNSUpstream: "1.1.1.1:53", DefaultPolicyProfile: "balanced", DefaultCPUs: 4, DefaultMemoryMiB: 2048, DockerVolumeSize: "20g"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got != want {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := Save(path, Values{DNSUpstream: "1.1.1.1:53"}); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err != nil || got.DNSUpstream != "1.1.1.1:53" || got.DefaultCPUs != 0 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestLoadRejectsUnknownAndUnsafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.toml")
	if err := os.WriteFile(path, []byte("nope = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("err=%v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("err=%v", err)
	}
}
