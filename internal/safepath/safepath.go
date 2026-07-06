// Package safepath centralizes filesystem-path and executable-path
// validation: every file the agent touches through a variable path, and every
// external binary it spawns, goes through here first. The functions implement
// the sanitize-then-verify pattern (absolutize + Clean + containment checks)
// so no caller ever hands raw, unvalidated input to a filesystem or exec sink.
package safepath

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// CleanAbs sanitizes a path: rejects empty input, absolutizes, and Cleans —
// removing every ".." and "." segment by construction.
func CleanAbs(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	return filepath.Clean(abs), nil
}

// Under joins name onto baseDir and guarantees the result cannot escape
// baseDir (path-traversal containment).
func Under(baseDir, name string) (string, error) {
	cleanBase, err := CleanAbs(baseDir)
	if err != nil {
		return "", err
	}
	joined := filepath.Clean(filepath.Join(cleanBase, name))
	rel, err := filepath.Rel(cleanBase, joined)
	if err != nil {
		return "", fmt.Errorf("resolve %q under %q: %w", name, cleanBase, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes base directory", name)
	}
	return joined, nil
}

// WriteFile is THE way this agent writes a file — config's atomicWrite,
// moved here so every content write in every package shares the one shape:
// sanitize the path, write the bytes to a temp file beside the target
// through a file handle (the sink only ever sees a Cleaned path), rename
// into place so no reader ever observes a partial file. perm is the file
// mode (most agent files are private state, 0600).
func WriteFile(path string, data []byte, perm os.FileMode) error {
	clean, err := CleanAbs(path)
	if err != nil {
		return err
	}
	tmp := clean + ".tmp"

	f, err := os.OpenFile(filepath.Clean(tmp), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	return os.Rename(tmp, clean)
}

// WriteFileFrom is WriteFile's streaming variant — same guarantees
// (sanitized path, temp file beside the target, rename into place), for
// content too large to buffer (installer files, downloads). Returns the
// byte count written.
func WriteFileFrom(path string, r io.Reader, perm os.FileMode) (int64, error) {
	clean, err := CleanAbs(path)
	if err != nil {
		return 0, err
	}
	tmp := clean + ".tmp"

	f, err := os.OpenFile(filepath.Clean(tmp), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return n, err
	}
	if rerr := os.Rename(tmp, clean); rerr != nil {
		_ = os.Remove(tmp)
		return n, rerr
	}
	return n, nil
}

// ValidateExecutable sanitizes an executable path and verifies it points at
// a real, regular, executable file — the gate every spawned binary passes
// before reaching exec.
func ValidateExecutable(path string) (string, error) {
	clean, err := CleanAbs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("stat executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file", clean)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("%q is not executable", clean)
	}
	return clean, nil
}

// ValidateAppBundle sanitizes a macOS .app bundle path and verifies it is a
// directory ending in .app (the shape `open -a` expects).
func ValidateAppBundle(path string) (string, error) {
	clean, err := CleanAbs(path)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(clean, ".app") {
		return "", fmt.Errorf("%q is not a .app bundle", clean)
	}
	info, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("stat app bundle: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q is not a directory", clean)
	}
	return clean, nil
}
