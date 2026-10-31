package command

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// writeRootedCopyTar keeps all source lookups below an open directory handle.
// Absolute symlinks are rejected by os.Root even when they point inside it.
func writeRootedCopyTar(w io.Writer, root *os.Root, source, top string, follow bool) error {
	tw := tar.NewWriter(w)
	b := rootedCopyBuilder{root: root, tw: tw, follow: follow}
	err := b.add(source, top, nil)
	return errors.Join(err, tw.Close())
}

type rootedCopyBuilder struct {
	root    *os.Root
	tw      *tar.Writer
	follow  bool
	entries int
	total   int64
}

func (b *rootedCopyBuilder) add(source, name string, ancestors []os.FileInfo) error {
	linkInfo, err := b.root.Lstat(source)
	if err != nil {
		return err
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 && !b.follow {
		return fmt.Errorf("symbolic link %s is not supported", source)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 && !linkInfo.IsDir() && !linkInfo.Mode().IsRegular() {
		return fmt.Errorf("unsupported file type at %s", source)
	}
	file, err := openCopySource(b.root, source)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 && !os.SameFile(linkInfo, info) {
		return errors.New("source changed while opening")
	}
	if err := b.validateEntry(info, source); err != nil {
		return err
	}
	if err := b.writeHeader(info, name); err != nil {
		return err
	}
	if !info.IsDir() {
		_, err := io.CopyN(b.tw, file, info.Size())
		return err
	}
	return b.addDirectory(file, source, name, info, ancestors)
}

func (b *rootedCopyBuilder) validateEntry(info os.FileInfo, source string) error {
	if !info.IsDir() && !info.Mode().IsRegular() {
		return fmt.Errorf("unsupported file type at %s", source)
	}
	if info.Mode().IsRegular() {
		if err := rejectCopyHardlink(info); err != nil {
			return err
		}
		b.total += info.Size()
		if b.total > maxCopyBytes {
			return errors.New("source is too large")
		}
	}
	b.entries++
	if b.entries > maxCopyEntries {
		return errors.New("source has too many entries")
	}
	return nil
}

func (b *rootedCopyBuilder) writeHeader(info os.FileInfo, name string) error {
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(name)
	if info.IsDir() {
		header.Name += "/"
	}
	header.Uid, header.Gid, header.Uname, header.Gname = 0, 0, "", ""
	header.AccessTime, header.ChangeTime = time.Time{}, time.Time{}
	header.Format = tar.FormatUSTAR
	return b.tw.WriteHeader(header)
}

func (b *rootedCopyBuilder) addDirectory(file *os.File, source, name string, info os.FileInfo, ancestors []os.FileInfo) error {
	for _, ancestor := range ancestors {
		if os.SameFile(ancestor, info) {
			return fmt.Errorf("symbolic link cycle at %s", source)
		}
	}
	ancestors = append(ancestors, info)
	for {
		entries, err := file.ReadDir(128)
		for _, entry := range entries {
			if err := b.add(filepath.Join(source, entry.Name()), filepath.Join(name, entry.Name()), ancestors); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
