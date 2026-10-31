package command

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	sdk "github.com/KLORQ/sandboxes-go-sdk"
)

const cpUsage = `usage: ksbx cp SRC DST

Copy one file or directory between the host and a sandbox. Exactly one side
must be SANDBOX:PATH with an absolute guest path. The destination is the exact
target path; an existing host directory is used as a directory container.
Symbolic links, hard links and special files are rejected by default. -L follows
a top-level source symlink (nested links remain rejected). Directory trees and
regular files are supported.`

type copySpec struct {
	sandbox string
	path    string
}

func parseCopySpec(value string) (copySpec, bool) {
	index := strings.IndexByte(value, ':')
	if index <= 0 || index == len(value)-1 {
		return copySpec{}, false
	}
	return copySpec{sandbox: value[:index], path: value[index+1:]}, true
}

func (r *Runner) cp(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	follow := fs.Bool("L", false, "follow a top-level source symbolic link")
	fs.BoolVar(follow, "follow-link", false, "follow a top-level source symbolic link")
	fs.Usage = func() { _, _ = fmt.Fprint(r.Err, cpUsage) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 2 {
		_, _ = fmt.Fprintln(r.Err, cpUsage)
		return 2
	}
	src, srcGuest := parseCopySpec(fs.Arg(0))
	dst, dstGuest := parseCopySpec(fs.Arg(1))
	if srcGuest == dstGuest {
		_, _ = fmt.Fprintln(r.Err, "exactly one of SRC or DST must be SANDBOX:PATH")
		return 2
	}
	spec := dst
	if srcGuest {
		spec = src
	}
	client, err := r.client()
	if err != nil {
		r.error(err)
		return 1
	}
	defer func() { _ = client.Close() }()
	id, err := findExecSandbox(ctx, client, spec.sandbox)
	if err != nil {
		r.error(err)
		return 1
	}
	if srcGuest {
		err = copyGuestToHost(ctx, client, id, src.path, fs.Arg(1), *follow)
	} else {
		sb, getErr := client.Sandboxes().Get(ctx, id)
		if getErr != nil {
			r.error(getErr)
			return 1
		}
		err = copyHostToGuest(ctx, client, id, fs.Arg(0), dst.path, sb.Workspaces, *follow)
	}
	if err != nil {
		r.error(err)
		return 1
	}
	return 0
}

func copyHostToGuest(ctx context.Context, client sdk.Client, sandboxID, hostSource, guestTarget string, workspaces []sdk.Workspace, followLink bool) error {
	source, err := filepath.Abs(hostSource)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(source); err != nil {
		return err
	}
	root, rootedSource, err := copyWorkspaceRoot(source, workspaces)
	if err != nil {
		return err
	}
	if root != nil {
		defer func() { _ = root.Close() }()
	}
	if root == nil {
		source, err = resolveCopySource(source, workspaces, followLink)
		if err != nil {
			return err
		}
	}
	target, err := resolveHostCopyTarget(ctx, client, sandboxID, guestTarget, source)
	if err != nil {
		return err
	}
	base, parent := path.Base(target), path.Dir(target)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	session, err := sdk.Sessions(client).OpenSession(ctx, sdk.SessionRequest{
		SandboxID: sandboxID,
		Argv:      []string{shellPath, "-c", `mkdir -p "$1" && exec tar -xf - -C "$1"`, "klorq-cp", parent},
	})
	if err != nil {
		return err
	}
	writerDone := make(chan error, 1)
	go func() {
		err := writeHostCopy(copySessionWriter{session: session}, root, rootedSource, source, base, workspaces, followLink)
		closeErr := session.CloseInput()
		writerDone <- errors.Join(err, closeErr)
		if err != nil {
			cancel()
		}
	}()
	stderr, code, err := receiveCopyOutput(session, io.Discard)
	cancel()
	if err != nil {
		if writerErr := <-writerDone; writerErr != nil {
			return writerErr
		}
		return err
	}
	if err := <-writerDone; err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("guest tar failed with exit %d: %s", code, strings.TrimSpace(stderr))
	}
	return nil
}

func writeHostCopy(w io.Writer, root *os.Root, rootedSource, source, base string, workspaces []sdk.Workspace, follow bool) error {
	switch {
	case root != nil:
		return writeRootedCopyTar(w, root, rootedSource, base, follow)
	case follow:
		return writeCopyTarFollow(w, source, base, workspaces)
	default:
		return writeCopyTar(w, source, base)
	}
}

func resolveCopySource(source string, workspaces []sdk.Workspace, follow bool) (string, error) {
	if !follow {
		return source, nil
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", err
	}
	if err := ensureFollowInsideWorkspace(source, resolved, workspaces); err != nil {
		return "", err
	}
	return resolved, nil
}

func copyWorkspaceRoot(source string, workspaces []sdk.Workspace) (*os.Root, string, error) {
	parent, parentErr := filepath.EvalSymlinks(filepath.Dir(source))
	for _, workspace := range workspaces {
		workspacePath, err := filepath.Abs(workspace.Path)
		if err != nil {
			return nil, "", err
		}
		candidate := source
		if !pathWithin(workspacePath, candidate) && parentErr == nil {
			workspacePath, err = filepath.EvalSymlinks(workspacePath)
			if err != nil {
				return nil, "", err
			}
			candidate = filepath.Join(parent, filepath.Base(source))
		}
		if !pathWithin(workspacePath, candidate) {
			continue
		}
		relative, err := filepath.Rel(workspacePath, candidate)
		if err != nil {
			return nil, "", err
		}
		root, err := os.OpenRoot(workspacePath)
		return root, relative, err
	}
	return nil, "", nil
}

func copyGuestToHost(ctx context.Context, client sdk.Client, sandboxID, guestSource, hostTarget string, followLink bool) error {
	source, err := cleanGuestPath(guestSource)
	if err != nil {
		return err
	}
	base, parent := path.Base(source), path.Dir(source)
	if strings.HasPrefix(base, "-") {
		return errors.New("guest source basename must not start with '-'")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tarArgs := []string{"tar"}
	if followLink {
		tarArgs = append(tarArgs, "-h")
	}
	tarArgs = append(tarArgs, "-cf", "-", "-C", parent, base)
	session, err := sdk.Sessions(client).OpenSession(ctx, sdk.SessionRequest{
		SandboxID: sandboxID,
		Argv:      tarArgs,
	})
	if err != nil {
		return err
	}
	if err := session.CloseInput(); err != nil {
		return err
	}
	reader, writer := io.Pipe()
	extractDone := make(chan error, 1)
	go func() {
		err := extractCopyTar(reader, hostTarget, base)
		_ = reader.CloseWithError(err)
		extractDone <- err
		if err != nil {
			cancel()
		}
	}()
	stderr, code, err := receiveCopyOutput(session, writer)
	cancel()
	if err != nil {
		_ = writer.CloseWithError(err)
		extractErr := <-extractDone
		return errors.Join(err, extractErr)
	}
	if err := writer.Close(); err != nil {
		extractErr := <-extractDone
		return errors.Join(err, extractErr)
	}
	if err := <-extractDone; err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("guest tar failed with exit %d: %s", code, strings.TrimSpace(stderr))
	}
	return nil
}

func receiveCopyOutput(session sdk.ExecSession, stdout io.Writer) (string, int, error) {
	var stderr bytes.Buffer
	for {
		frame, err := session.Receive()
		if err != nil {
			return "", 0, err
		}
		if len(frame.Stdout) > 0 {
			n, err := stdout.Write(frame.Stdout)
			if err != nil {
				return "", 0, err
			}
			if n != len(frame.Stdout) {
				return "", 0, io.ErrShortWrite
			}
		}
		if len(frame.Stderr) > 0 && stderr.Len() < 8192 {
			_, _ = stderr.Write(frame.Stderr[:min(len(frame.Stderr), 8192-stderr.Len())])
		}
		if frame.ExitCode != nil {
			return stderr.String(), *frame.ExitCode, nil
		}
	}
}

func resolveHostCopyTarget(ctx context.Context, client sdk.Client, sandboxID, guestTarget, source string) (string, error) {
	target, err := hostCopyTarget(guestTarget, source, false)
	if err != nil || strings.HasSuffix(guestTarget, "/") {
		return target, err
	}
	isDir, err := guestDirectoryExists(ctx, client, sandboxID, target)
	if err != nil || !isDir {
		return target, err
	}
	return hostCopyTarget(guestTarget, source, true)
}

func hostCopyTarget(guestTarget, source string, destinationIsDir bool) (string, error) {
	directory := destinationIsDir || strings.HasSuffix(guestTarget, "/")
	target, err := cleanGuestPath(guestTarget)
	if err != nil {
		return "", err
	}
	if directory {
		target = path.Join(target, filepath.Base(source))
	}
	return target, nil
}

func guestDirectoryExists(ctx context.Context, client sdk.Client, sandboxID, guestPath string) (bool, error) {
	var stderr bytes.Buffer
	code, err := sdk.ExecService(client).Exec(ctx, sdk.ExecRequest{
		SandboxID: sandboxID,
		Argv:      []string{shellPath, "-c", `test -d "$1"`, "klorq-cp", guestPath},
		Stdout:    io.Discard,
		Stderr:    &stderr,
	})
	if err != nil {
		return false, err
	}
	switch code {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("inspect guest destination: exit %d: %s", code, strings.TrimSpace(stderr.String()))
	}
}

func cleanGuestPath(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("guest path is invalid")
	}
	clean := path.Clean(value)
	if !path.IsAbs(clean) || clean == "/" || clean == "." {
		return "", errors.New("guest path must be an absolute path other than /")
	}
	return clean, nil
}

type copySessionWriter struct{ session sdk.ExecSession }

func (w copySessionWriter) Write(p []byte) (int, error) {
	if err := w.session.SendInput(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func ensureFollowInsideWorkspace(source, target string, workspaces []sdk.Workspace) error {
	sourceReal, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	targetReal, err := filepath.EvalSymlinks(target)
	if err != nil {
		return err
	}
	sourceDir, err := filepath.EvalSymlinks(filepath.Dir(source))
	if err != nil {
		return err
	}
	sourceLocation := filepath.Join(sourceDir, filepath.Base(source))
	for i := range workspaces {
		workspaceReal, err := filepath.EvalSymlinks(workspaces[i].Path)
		if err != nil {
			return fmt.Errorf("resolve workspace %s: %w", workspaces[i].Path, err)
		}
		if !pathWithin(workspaceReal, sourceLocation) && !pathWithin(workspaces[i].Path, source) && !pathWithin(workspaceReal, sourceReal) {
			continue
		}
		if !pathWithin(workspaceReal, targetReal) {
			return fmt.Errorf("symbolic link target %s escapes sandbox workspace %s", target, workspaces[i].Path)
		}
		return nil
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil || filepath.IsAbs(relative) {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}
