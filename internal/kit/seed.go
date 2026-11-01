package kit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// SeedCacheRoot returns the host cache for kit workspace seeds.
func SeedCacheRoot() string {
	if dir := os.Getenv("XDG_CACHE_HOME"); dir != "" {
		return filepath.Join(dir, "klorq", "kits")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".cache", "klorq", "kits")
}

// ResolveSeed clones seed once into a deterministic host cache and returns the
// workspace path. Git hooks are disabled, depth is one, and no shell is used.
// The cache is a host-owned directory, not a guest-writable mount.
func ResolveSeed(ctx context.Context, seed, cacheRoot string) (string, error) {
	if err := validateSeed(seed); err != nil {
		return "", err
	}
	if cacheRoot == "" {
		return "", errors.New("kit seed cache directory is unavailable")
	}
	sum := sha256.Sum256([]byte(seed))
	dest := filepath.Join(cacheRoot, hex.EncodeToString(sum[:12]))
	if info, err := os.Stat(dest); err == nil && info.IsDir() {
		return dest, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect kit seed cache: %w", err)
	}
	if err := os.MkdirAll(cacheRoot, 0o700); err != nil {
		return "", fmt.Errorf("create kit seed cache: %w", err)
	}
	temp, err := os.MkdirTemp(cacheRoot, ".clone-*")
	if err != nil {
		return "", fmt.Errorf("create kit seed temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(temp) }()
	cloneCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cloneCtx, "git", // #nosec G204 -- fixed git binary and validated URL
		"-c", "core.hooksPath=/dev/null",
		"clone", "--depth", "1", "--no-tags", "--", seed, temp,
	)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = output
		return "", fmt.Errorf("clone kit workspace seed: %w", err)
	}
	if err := os.Rename(temp, dest); err != nil {
		if info, statErr := os.Stat(dest); statErr == nil && info.IsDir() {
			return dest, nil
		}
		return "", fmt.Errorf("install kit seed cache: %w", err)
	}
	return dest, nil
}
