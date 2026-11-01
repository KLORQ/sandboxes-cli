// Package settings reads and writes the host-side Klorq settings file.
package settings

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Values are the supported user overrides.
type Values struct {
	DNSUpstream          string
	DefaultPolicyProfile string
	DefaultCPUs          uint32
	DefaultMemoryMiB     uint32
	DockerVolumeSize     string
}

// DefaultPath returns ~/.config/klorq/settings.toml, honoring XDG_CONFIG_HOME.
func DefaultPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "klorq", "settings.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "klorq", "settings.toml")
}

// Load reads the optional settings file. A missing file is not an error.
func Load(path string) (Values, error) {
	var values Values
	if path == "" {
		return values, nil
	}
	file, err := os.Open(path) // #nosec G304 -- path is the user settings location
	if errors.Is(err, os.ErrNotExist) {
		return values, nil
	}
	if err != nil {
		return values, fmt.Errorf("open settings: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return values, fmt.Errorf("stat settings: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return values, errors.New("settings file must be a regular file not writable by group or others")
	}
	if err := parse(file, &values); err != nil {
		return values, err
	}
	return values, nil
}

func parse(r io.Reader, values *Values) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		if !found {
			return fmt.Errorf("settings line %d: expected key = value", lineNumber)
		}
		key = strings.TrimSpace(key)
		value, err := parseValue(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("settings line %d: %w", lineNumber, err)
		}
		switch key {
		case "dns_upstream":
			values.DNSUpstream = value
		case "default_policy_profile":
			values.DefaultPolicyProfile = value
		case "default_cpus":
			parsed, err := parseUint(key, value, 32)
			if err != nil {
				return err
			}
			values.DefaultCPUs = uint32(parsed) //nolint:gosec // parsed with 32 bits and validated below.
		case "default_memory_mib":
			parsed, err := parseUint(key, value, 32)
			if err != nil {
				return err
			}
			values.DefaultMemoryMiB = uint32(parsed) //nolint:gosec // parsed with 32 bits and validated below.
		case "docker_volume_size":
			values.DockerVolumeSize = value
		default:
			return fmt.Errorf("settings line %d: unknown key %q", lineNumber, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	return nil
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty value")
	}
	if raw[0] != '"' {
		return raw, nil
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("invalid quoted string: %w", err)
	}
	return value, nil
}

func parseUint(key, value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return parsed, nil
}

// Save atomically writes all values. Empty values are omitted.
func Save(path string, values Values) error {
	if path == "" {
		return errors.New("settings path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create settings directory: %w", err)
	}
	entries := make([]string, 0, 5)
	if values.DNSUpstream != "" {
		entries = append(entries, "dns_upstream = "+strconv.Quote(values.DNSUpstream))
	}
	if values.DefaultPolicyProfile != "" {
		entries = append(entries, "default_policy_profile = "+strconv.Quote(values.DefaultPolicyProfile))
	}
	if values.DefaultCPUs != 0 {
		entries = append(entries, "default_cpus = "+strconv.FormatUint(uint64(values.DefaultCPUs), 10))
	}
	if values.DefaultMemoryMiB != 0 {
		entries = append(entries, "default_memory_mib = "+strconv.FormatUint(uint64(values.DefaultMemoryMiB), 10))
	}
	if values.DockerVolumeSize != "" {
		entries = append(entries, "docker_volume_size = "+strconv.Quote(values.DockerVolumeSize))
	}
	sort.Strings(entries)
	body := "# Klorq host settings. Managed by ksbx settings; do not put secrets here.\n"
	if len(entries) > 0 {
		body += strings.Join(entries, "\n") + "\n"
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".settings-*")
	if err != nil {
		return fmt.Errorf("create settings temp file: %w", err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("chmod settings temp file: %w", err)
	}
	if _, err := temp.WriteString(body); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write settings: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync settings: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close settings: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace settings: %w", err)
	}
	return nil
}
