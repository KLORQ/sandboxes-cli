package command

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	maxExecEnvEntries = 256
	maxExecEnvEntry   = 64 * 1024
	maxExecEnvTotal   = 256 * 1024
	maxExecEnvFile    = 1024 * 1024
)

func buildExecEnv(entries, files []string) ([]string, error) {
	env := make([]string, 0, len(entries))
	for _, path := range files {
		values, err := readExecEnvFile(path)
		if err != nil {
			return nil, err
		}
		env = append(env, values...)
	}
	for _, entry := range entries {
		resolved, ok, err := resolveExecEnvEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid --env override: %w", err)
		}
		if ok {
			env = append(env, resolved)
		}
	}
	if len(env) > maxExecEnvEntries {
		return nil, errors.New("too many environment overrides")
	}
	total := 0
	for _, entry := range env {
		total += len(entry)
		if total > maxExecEnvTotal {
			return nil, errors.New("environment overrides are too large")
		}
	}
	return env, nil
}

func readExecEnvFile(path string) ([]string, error) {
	file, err := os.Open(path) //nolint:gosec // The user explicitly supplies this env-file path.
	if err != nil {
		return nil, fmt.Errorf("open env file: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxExecEnvFile+1))
	if err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	if len(data) > maxExecEnvFile {
		return nil, errors.New("env file is too large")
	}
	lines := strings.Split(string(data), "\n")
	env := make([]string, 0, len(lines))
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSpace(line) != line {
			return nil, fmt.Errorf("env file line %d must not have surrounding whitespace", i+1)
		}
		if err := validateExecEnvEntry(line); err != nil {
			return nil, fmt.Errorf("env file line %d: %w", i+1, err)
		}
		env = append(env, line)
	}
	return env, nil
}

func resolveExecEnvEntry(entry string) (string, bool, error) {
	if strings.Contains(entry, "=") {
		if err := validateExecEnvEntry(entry); err != nil {
			return "", false, err
		}
		return entry, true, nil
	}
	if !validExecEnvKey(entry) {
		return "", false, errors.New("environment name must match [A-Za-z_][A-Za-z0-9_]*")
	}
	value, ok := os.LookupEnv(entry)
	if !ok {
		return "", false, nil
	}
	return entry + "=" + value, true, nil
}

func validateExecEnvEntry(entry string) error {
	if len(entry) > maxExecEnvEntry {
		return errors.New("override is too large")
	}
	if strings.ContainsRune(entry, '\x00') {
		return errors.New("override contains NUL")
	}
	key, _, ok := strings.Cut(entry, "=")
	if !ok {
		return errors.New("must be KEY=VALUE; copying host environment variables is not supported")
	}
	if !validExecEnvKey(key) {
		return errors.New("environment name must match [A-Za-z_][A-Za-z0-9_]*")
	}
	return nil
}

func validExecEnvKey(name string) bool {
	if name == "" || len(name) > 255 || !envNameStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !envNameChar(name[i]) {
			return false
		}
	}
	return true
}

func envNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func envNameChar(c byte) bool {
	return envNameStart(c) || (c >= '0' && c <= '9')
}

func validateExecUser(user string) error {
	if user == "" {
		return nil
	}
	if len(user) > 64 || strings.ContainsRune(user, '\x00') {
		return errors.New("user must be uid[:gid] or name[:group]")
	}
	parts := strings.Split(user, ":")
	if len(parts) > 2 || !validUserToken(parts[0]) {
		return errors.New("user must be uid[:gid] or name[:group]")
	}
	if len(parts) == 2 && !validUserToken(parts[1]) {
		return errors.New("user group must be gid or group name")
	}
	return nil
}

func validUserToken(token string) bool {
	if token == "" {
		return false
	}
	if _, err := strconv.ParseUint(token, 10, 32); err == nil {
		return true
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || (i > 0 && ((c >= '0' && c <= '9') || c == '-' || c == '.')) {
			continue
		}
		return false
	}
	return true
}

func envMap(entries []string) map[string]string {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			out[key] = value
		}
	}
	return out
}
