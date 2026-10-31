package command

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const (
	maxCopyEntries = 100000
	maxCopyBytes   = int64(4 << 30)
)

type copyTarBuilder struct {
	tw      *tar.Writer
	entries int
	total   int64
}

func writeCopyTar(w io.Writer, source, top string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic links are not supported by cp yet")
	}
	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()
	builder := &copyTarBuilder{tw: tw}
	if !info.IsDir() {
		return builder.add(source, info, top)
	}
	return builder.addTree(source, top)
}

func writeCopyTarFollow(w io.Writer, source, top string, workspaces []sdk.Workspace) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(source)
		if err != nil {
			return err
		}
		if err := ensureFollowInsideWorkspace(source, resolved, workspaces); err != nil {
			return err
		}
		source = resolved
		if info, err = os.Stat(source); err != nil {
			return err
		}
	}
	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()
	builder := &copyTarBuilder{tw: tw}
	if !info.IsDir() {
		return builder.add(source, info, top)
	}
	return builder.addTreeFollow(source, top, workspaces, make(map[string]bool))
}

func (b *copyTarBuilder) addTreeFollow(source, top string, workspaces []sdk.Workspace, stack map[string]bool) error {
	realSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	if stack[realSource] {
		return fmt.Errorf("symbolic link cycle at %s", source)
	}
	stack[realSource] = true
	defer delete(stack, realSource)
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if err := b.add(source, info, top+"/"); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := b.addFollowChild(filepath.Join(source, entry.Name()), top+"/"+entry.Name(), workspaces, stack); err != nil {
			return err
		}
	}
	return nil
}

func (b *copyTarBuilder) addFollowChild(child, name string, workspaces []sdk.Workspace, stack map[string]bool) error {
	info, err := os.Lstat(child)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return b.addFollowLink(child, name, workspaces, stack)
	}
	if info.IsDir() {
		return b.addTreeFollow(child, name, workspaces, stack)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported file type at %s", child)
	}
	return b.add(child, info, name)
}

func (b *copyTarBuilder) addFollowLink(link, name string, workspaces []sdk.Workspace, stack map[string]bool) error {
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		return err
	}
	if err := ensureFollowInsideWorkspace(link, resolved, workspaces); err != nil {
		return err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return b.addTreeFollow(resolved, name, workspaces, stack)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported file type at %s", link)
	}
	return b.add(resolved, info, name)
}

func (b *copyTarBuilder) addTree(source, top string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if err := b.add(source, info, top+"/"); err != nil {
		return err
	}
	return filepath.Walk(source, func(current string, currentInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == source {
			return nil
		}
		if err := validateCopySource(current, currentInfo); err != nil {
			return err
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		name := top + "/" + filepath.ToSlash(relative)
		if currentInfo.IsDir() {
			name += "/"
		}
		return b.add(current, currentInfo, name)
	})
}

func validateCopySource(current string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symbolic link %s is not supported by cp yet", current)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return fmt.Errorf("unsupported file type at %s", current)
	}
	return nil
}

func (b *copyTarBuilder) add(filePath string, info os.FileInfo, name string) error {
	b.entries++
	if b.entries > maxCopyEntries {
		return errors.New("source has too many entries")
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = name
	header.Uid, header.Gid = 0, 0
	header.Uname, header.Gname = "", ""
	header.Mode = int64(info.Mode().Perm())
	header.AccessTime = time.Time{}
	header.ChangeTime = time.Time{}
	// BusyBox tar (the default guest userland) misreads GNU atime/ctime
	// fields as a path prefix, so use the portable USTAR layout.
	header.Format = tar.FormatUSTAR
	if err := b.tw.WriteHeader(header); err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if err := rejectCopyHardlink(info); err != nil {
		return err
	}
	b.total += info.Size()
	if b.total > maxCopyBytes {
		return errors.New("source is too large")
	}
	file, err := openCopyPath(filePath)
	if err != nil {
		return err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		return errors.New("source changed while opening")
	}
	if err := rejectCopyHardlink(openedInfo); err != nil {
		_ = file.Close()
		return err
	}
	n, copyErr := io.Copy(b.tw, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != info.Size() {
		return errors.New("source file changed while copying")
	}
	return nil
}

func extractCopyTar(r io.Reader, dest, expectedTop string) error {
	dest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	rootDir, targetBase, stripTop, err := copyExtractionPlan(dest)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tr := tar.NewReader(r)
	entries := 0
	var total int64
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxCopyEntries {
			return errors.New("archive has too many entries")
		}
		target, err := copyTargetName(header.Name, expectedTop, targetBase, stripTop)
		if err != nil {
			return err
		}
		if err := extractCopyEntry(root, target, header, tr, &total); err != nil {
			return err
		}
	}
}

func copyExtractionPlan(dest string) (rootDir, targetBase string, stripTop bool, err error) {
	info, err := os.Lstat(dest)
	switch {
	case err == nil && info.IsDir():
		return dest, filepath.Base(dest), false, nil
	case err == nil:
		// An existing file is the exact target and is replaced atomically by
		// the extractor after a safe unlink.
		return filepath.Dir(dest), filepath.Base(dest), true, nil
	case !errors.Is(err, os.ErrNotExist):
		return "", "", false, err
	}
	rootDir = filepath.Dir(dest)
	if err := os.MkdirAll(rootDir, 0o750); err != nil {
		return "", "", false, err
	}
	return rootDir, filepath.Base(dest), true, nil
}

func extractCopyEntry(root *os.Root, target string, header *tar.Header, r io.Reader, total *int64) error {
	switch header.Typeflag {
	case tar.TypeDir:
		return root.MkdirAll(target, 0o750)
	case tar.TypeReg:
		if header.Size < 0 || header.Size > maxCopyBytes {
			return errors.New("archive entry is too large")
		}
		*total += header.Size
		if *total > maxCopyBytes {
			return errors.New("archive is too large")
		}
		if header.Mode < 0 || header.Mode > 0o7777 {
			return errors.New("archive entry has an invalid mode")
		}
		return writeCopyFile(root, target, r, header.Size, os.FileMode(header.Mode))
	case tar.TypeSymlink, tar.TypeLink:
		return errors.New("symbolic and hard links are not supported by cp yet")
	default:
		return fmt.Errorf("unsupported archive entry type for %s", header.Name)
	}
}

func copyTargetName(name, expectedTop, targetBase string, stripTop bool) (string, error) {
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	if clean == "." || clean == "" || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	if clean != expectedTop && !strings.HasPrefix(clean, expectedTop+"/") {
		return "", fmt.Errorf("archive entry %q is outside %q", name, expectedTop)
	}
	if !stripTop {
		return clean, nil
	}
	relative := strings.TrimPrefix(clean, expectedTop)
	relative = strings.TrimPrefix(relative, "/")
	if relative == "" {
		return targetBase, nil
	}
	return path.Join(targetBase, relative), nil
}

func writeCopyFile(root *os.Root, name string, r io.Reader, size int64, mode os.FileMode) error {
	if parent := path.Dir(name); parent != "." {
		if err := root.MkdirAll(parent, 0o750); err != nil {
			return err
		}
	}
	if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.CopyN(file, r, size)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != size {
		return io.ErrUnexpectedEOF
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	return root.Chmod(name, perm)
}
