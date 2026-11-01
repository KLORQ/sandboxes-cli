package command

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteAndExtractCopyTarFile(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source.txt")
	if err := os.WriteFile(source, []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writeCopyTar(&archive, source, "target.txt"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "target.txt")
	if err := extractCopyTar(&archive, dest, "target.txt"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "payload" {
		t.Fatalf("dest=%q err=%v", data, err)
	}
	info, err := os.Stat(dest)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%v err=%v", info.Mode(), err)
	}
}

func TestWriteAndExtractCopyTarDirectory(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writeCopyTar(&archive, source, "target"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "target")
	if err := extractCopyTar(&archive, dest, "target"); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a.txt": "a", "sub/b.txt": "b"} {
		data, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil || string(data) != want {
			t.Fatalf("%s=%q err=%v", name, data, err)
		}
	}
}

func TestExtractCopyTarIntoExistingDirectory(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writeCopyTar(&archive, source, "source"); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := extractCopyTar(&archive, dest, "source"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "source")); err != nil || string(data) != "file" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}

func TestExtractCopyTarRejectsUnrelatedEntryInExistingDirectory(t *testing.T) {
	dest := t.TempDir()
	victim := filepath.Join(dest, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, "data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "victim", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractCopyTar(&archive, dest, "source"); err == nil {
		t.Fatal("accepted an entry outside the requested source")
	}
	data, err := os.ReadFile(filepath.Join(victim, "data"))
	if err != nil || string(data) != "keep" {
		t.Fatalf("victim data=%q err=%v", data, err)
	}
}

func TestExtractCopyTarDoesNotRemoveNonemptyDirectory(t *testing.T) {
	dest := t.TempDir()
	target := filepath.Join(dest, "source")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "data"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "source", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractCopyTar(&archive, dest, "source"); err == nil {
		t.Fatal("replaced a nonempty directory")
	}
	if _, err := os.Stat(filepath.Join(target, "data")); err != nil {
		t.Fatal(err)
	}
}

func TestExtractCopyTarRejectsTraversalAndLinks(t *testing.T) {
	for name, header := range map[string]*tar.Header{
		"traversal": {Name: "../escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
		"absolute":  {Name: "/escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644},
		"symlink":   {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
		"hardlink":  {Name: "hard", Typeflag: tar.TypeLink, Linkname: "link"},
	} {
		var archive bytes.Buffer
		tw := tar.NewWriter(&archive)
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(t.TempDir(), "dest")
		if err := extractCopyTar(&archive, dest, "source"); err == nil {
			t.Fatalf("%s entry was accepted", name)
		}
	}
}

func TestWriteCopyTarRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writeCopyTar(&archive, link, "link"); err == nil || !strings.Contains(err.Error(), "symbolic") {
		t.Fatalf("symlink source error = %v", err)
	}
}

func TestWriteCopyTarRejectsHardlink(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, filepath.Join(dir, "link")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := writeCopyTar(io.Discard, source, "source"); err == nil {
		t.Fatal("hard-linked source accepted")
	}
}

func TestParseCopySpec(t *testing.T) {
	for _, tc := range []struct {
		value   string
		ok      bool
		sandbox string
		path    string
	}{
		{"dev:/workspace/file", true, "dev", "/workspace/file"},
		{"/tmp/file", false, "", ""},
		{":/tmp/file", false, "", ""},
		{"dev:", false, "", ""},
	} {
		spec, ok := parseCopySpec(tc.value)
		if ok != tc.ok || spec.sandbox != tc.sandbox || spec.path != tc.path {
			t.Fatalf("parseCopySpec(%q)=%#v,%t", tc.value, spec, ok)
		}
	}
}

func TestCleanGuestPath(t *testing.T) {
	for _, value := range []string{"", "relative", "/", "/..", "/tmp/../etc"} {
		if value == "/tmp/../etc" {
			if got, err := cleanGuestPath(value); err != nil || got != "/etc" {
				t.Fatalf("cleanGuestPath(%q)=%q,%v", value, got, err)
			}
			continue
		}
		if _, err := cleanGuestPath(value); err == nil {
			t.Fatalf("cleanGuestPath(%q) accepted", value)
		}
	}
}

func TestExtractCopyTarReplacesExistingTargetFile(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writeCopyTar(&archive, source, "source"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(dest, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractCopyTar(&archive, dest, "source"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "new" {
		t.Fatalf("dest=%q err=%v", data, err)
	}
}

func TestHostCopyTargetHonorsTrailingSlash(t *testing.T) {
	source := filepath.Join(t.TempDir(), "file.txt")
	target, err := hostCopyTarget("/tmp/", source, false)
	if err != nil || target != "/tmp/file.txt" {
		t.Fatalf("target=%q err=%v", target, err)
	}
	target, err = hostCopyTarget("/tmp/name.txt", source, false)
	if err != nil || target != "/tmp/name.txt" {
		t.Fatalf("exact target=%q err=%v", target, err)
	}
	target, err = hostCopyTarget("/tmp", source, true)
	if err != nil || target != "/tmp/file.txt" {
		t.Fatalf("existing-dir target=%q err=%v", target, err)
	}
}

// TestExtractCopyTarSanitizesMetadata pins the P-37 sanitize contract: payload
// and permission bits survive, ownership, times, setuid/setgid and xattrs do
// not. This is intentionally weaker than full metadata parity.
func TestExtractCopyTarSanitizesMetadata(t *testing.T) {
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	header := &tar.Header{
		Name:     "source/file",
		Typeflag: tar.TypeReg,
		Mode:     0o4755,
		Size:     4,
		Uid:      4242,
		Gid:      4343,
		Uname:    "outside",
		Gname:    "outside",
		ModTime:  time.Unix(123456789, 0),
		PAXRecords: map[string]string{
			"user.test": "value",
		},
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "dest")
	if err := extractCopyTar(&archive, dest, "source"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "file"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		t.Fatalf("mode=%v", info.Mode())
	}
	if data, err := os.ReadFile(filepath.Join(dest, "file")); err != nil || string(data) != "data" {
		t.Fatalf("data=%q err=%v", data, err)
	}
}
