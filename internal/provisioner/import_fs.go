package provisioner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// findPackageRoot searches dir (breadth-first, rootSearchDepth levels) for a
// package root, preferring a collection root over a bare version root at any
// depth. Returns the winning manifest name as the kind ("" when neither
// exists).
func findPackageRoot(dir string) (root, kind string) {
	versionRoot := ""
	level := []string{dir}
	for depth := 0; depth <= rootSearchDepth; depth++ {
		next := []string{}
		for _, candidate := range level {
			if _, err := os.Stat(filepath.Join(candidate, collectionManifest)); err == nil {
				return candidate, collectionManifest
			}
			if versionRoot == "" {
				if _, err := os.Stat(filepath.Join(candidate, versionManifest)); err == nil {
					versionRoot = candidate
				}
			}
			entries, err := os.ReadDir(candidate)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != ".git" {
					next = append(next, filepath.Join(candidate, entry.Name()))
				}
			}
		}
		level = next
	}
	if versionRoot != "" {
		return versionRoot, versionManifest
	}
	return "", ""
}

// copyTree copies a package tree, preserving file modes, skipping .git
// DIRECTORIES (repo history stays out of the registry; the one-line gitlink
// FILES inside submodule checkouts are ordinary files and copy through —
// the observed SHI on-disk format keeps them) and skipping irregular
// entries.
func copyTree(src, dst string) error {
	cleanSrc, err := safepath.CleanAbs(src)
	if err != nil {
		return err
	}
	return filepath.WalkDir(cleanSrc, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(cleanSrc, path)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() && d.Name() == ".git" && rel != "." {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)

		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		switch {
		case d.IsDir():
			perm := info.Mode().Perm()
			if perm == 0 {
				perm = 0o750
			}
			return os.MkdirAll(target, perm)
		case info.Mode().IsRegular():
			return copyFile(path, target, info.Mode().Perm())
		default:
			// Symlinks and other irregulars never enter the registry.
			return nil
		}
	})
}

// copyFile copies one file with the given mode through the shared writer
// (safepath.WriteFile — the agent's ONE file-write path). An existing
// destination is replaced (the working-copy refresh relies on that); use
// copyFileIfAbsent where existing files must survive.
func copyFile(src, dst string, perm fs.FileMode) error {
	if perm == 0 {
		perm = 0o644
	}
	data, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return err
	}
	return safepath.WriteFile(dst, data, perm)
}

// synthesizeCollectionManifest writes a minimal family manifest when none
// exists — bare-version imports (the flattened repos: the root IS the
// version tree) and registry-shaped seed archives both arrive without one.
// An existing manifest is never touched.
func synthesizeCollectionManifest(familyDir, name, description string) error {
	manifestPath := filepath.Join(familyDir, collectionManifest)
	if _, err := os.Stat(manifestPath); err == nil {
		return nil
	}
	synthesized := "name: " + name + "\ndescription: " + strconv.Quote(description) + "\n"
	return safepath.WriteFile(manifestPath, []byte(synthesized), 0o644)
}

// copyFileIfAbsent copies src to dst unless dst already exists.
func copyFileIfAbsent(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return copyFile(src, dst, info.Mode().Perm())
}

// fileSHA256 hashes one file, streaming — the archive-checksum gate's hash
// (downloadVerified hashes in flight; here the file already sits on disk).
func fileSHA256(path string) (string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	hasher := sha256.New()
	if _, cerr := io.Copy(hasher, file); cerr != nil {
		return "", cerr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// gitPath returns the validated git path from the prerequisite detector, or
// "" when git is not installed.
func gitPath(ctx context.Context) string {
	for _, tool := range prereqs.Detect(ctx) {
		if tool.Name == "git" && tool.Installed {
			return tool.Path
		}
	}
	return ""
}

// streamCommand runs one external command, streaming stdout and stderr line
// by line into the task output (the vagrant package's streaming shape). The
// context is the kill switch (task cancellation, D-F).
func streamCommand(ctx context.Context, exe string, args []string, out *tasks.OutputWriter) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = procattr.NoConsole()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		forwardLines(stdout, "stdout", out)
	}()
	forwardLines(stderr, "stderr", out)
	<-stdoutDone

	return cmd.Wait()
}

// forwardLines feeds a pipe into the task output line by line.
func forwardLines(r io.Reader, stream string, out *tasks.OutputWriter) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		out.Write(stream, scanner.Text()+"\n")
	}
}
