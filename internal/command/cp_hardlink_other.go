//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package command

import (
	"errors"
	"os"
)

func rejectCopyHardlink(_ os.FileInfo) error {
	return errors.New("source hard link validation is unsupported on this platform")
}

func openCopySource(_ *os.Root, _ string) (*os.File, error) {
	return nil, errors.New("safe source opening is unsupported on this platform")
}

func openCopyPath(_ string) (*os.File, error) {
	return nil, errors.New("safe source opening is unsupported on this platform")
}
