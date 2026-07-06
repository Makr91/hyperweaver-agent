package provisioner

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// maxArchiveBytes bounds the total decompressed output of one archive — a
// decompression-bomb tripwire far above any real provisioner bundle.
const maxArchiveBytes = int64(32) << 30

// extractStats summarizes one extraction: files written, entries skipped
// (already present, pre-existing version dir, or irregular type).
type extractStats struct {
	Files   int
	Skipped int
}

// isArchive reports whether name looks like a provisioner archive this
// package can extract.
func isArchive(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".tar.gz") ||
		strings.HasSuffix(lower, ".tgz") ||
		strings.HasSuffix(lower, ".zip")
}

// extractArchive unpacks a provisioner archive (.tar.gz/.tgz/.zip) into
// destDir under the non-clobber rule (Mark's requirement — seeding and
// re-runs must be safe beside user-managed packages): existing files are
// never overwritten, and any <family>/<version> directory that existed
// before this call is skipped whole. Entry paths are containment-checked
// against destDir (zip-slip); irregular entries (symlinks, devices) are
// skipped and counted.
func extractArchive(archivePath, destDir string) (extractStats, error) {
	cleanDest, err := safepath.CleanAbs(destDir)
	if err != nil {
		return extractStats{}, err
	}
	if merr := os.MkdirAll(cleanDest, 0o700); merr != nil {
		return extractStats{}, fmt.Errorf("create destination: %w", merr)
	}

	x := &extraction{
		destDir:     cleanDest,
		preExisting: secondLevelDirs(cleanDest),
		remaining:   maxArchiveBytes,
	}
	lower := strings.ToLower(archivePath)
	if strings.HasSuffix(lower, ".zip") {
		err = x.extractZip(archivePath)
	} else {
		err = x.extractTarGz(archivePath)
	}
	return x.stats, err
}

// extraction carries one extraction pass's state.
type extraction struct {
	destDir     string
	preExisting map[string]bool
	remaining   int64
	stats       extractStats
}

func (x *extraction) extractTarGz(archivePath string) error {
	f, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() {
		_ = gz.Close()
	}()

	reader := tar.NewReader(gz)
	for {
		header, nerr := reader.Next()
		if errors.Is(nerr, io.EOF) {
			return nil
		}
		if nerr != nil {
			return fmt.Errorf("read tar entry: %w", nerr)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if werr := x.writeDir(header.Name, header.FileInfo().Mode().Perm()); werr != nil {
				return werr
			}
		case tar.TypeReg:
			if werr := x.writeFile(header.Name, header.FileInfo().Mode().Perm(), reader); werr != nil {
				return werr
			}
		default:
			// Symlinks, hardlinks, devices: never materialized from an
			// archive.
			x.stats.Skipped++
		}
	}
}

func (x *extraction) extractZip(archivePath string) error {
	zr, err := zip.OpenReader(filepath.Clean(archivePath))
	if err != nil {
		return err
	}
	defer func() {
		_ = zr.Close()
	}()

	for _, entry := range zr.File {
		mode := entry.Mode()
		switch {
		case mode.IsDir() || strings.HasSuffix(entry.Name, "/"):
			if werr := x.writeDir(entry.Name, mode.Perm()); werr != nil {
				return werr
			}
		case mode.IsRegular():
			rc, oerr := entry.Open()
			if oerr != nil {
				return fmt.Errorf("open zip entry %s: %w", entry.Name, oerr)
			}
			werr := x.writeFile(entry.Name, mode.Perm(), rc)
			_ = rc.Close()
			if werr != nil {
				return werr
			}
		default:
			x.stats.Skipped++
		}
	}
	return nil
}

// target containment-checks an entry name and applies the pre-existing
// version-directory skip. ok=false means the entry is skipped (counted).
func (x *extraction) target(entryName string) (path string, ok bool, err error) {
	normalized := strings.TrimPrefix(filepath.ToSlash(entryName), "./")
	target, err := safepath.Under(x.destDir, filepath.FromSlash(normalized))
	if err != nil {
		return "", false, fmt.Errorf("archive entry %q escapes destination: %w", entryName, err)
	}
	segments := strings.Split(strings.Trim(normalized, "/"), "/")
	if len(segments) >= 2 && x.preExisting[segments[0]+"/"+segments[1]] {
		x.stats.Skipped++
		return "", false, nil
	}
	return target, true, nil
}

func (x *extraction) writeDir(entryName string, perm fs.FileMode) error {
	target, ok, err := x.target(entryName)
	if err != nil || !ok {
		return err
	}
	if perm == 0 {
		perm = 0o750
	}
	return os.MkdirAll(target, perm)
}

func (x *extraction) writeFile(entryName string, perm fs.FileMode, r io.Reader) error {
	target, ok, err := x.target(entryName)
	if err != nil || !ok {
		return err
	}
	// The never-overwrite guarantee: an existing file (a user-managed
	// package member) survives every extraction pass.
	if _, serr := os.Stat(target); serr == nil {
		x.stats.Skipped++
		return nil
	}
	if perm == 0 {
		perm = 0o644
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return merr
	}

	data, rerr := io.ReadAll(io.LimitReader(r, x.remaining+1))
	if rerr != nil {
		return fmt.Errorf("extract %s: %w", entryName, rerr)
	}
	x.remaining -= int64(len(data))
	if x.remaining < 0 {
		return fmt.Errorf("archive exceeds the %d-byte extraction limit", maxArchiveBytes)
	}
	if werr := safepath.WriteFile(target, data, perm); werr != nil {
		return fmt.Errorf("extract %s: %w", entryName, werr)
	}
	x.stats.Files++
	return nil
}

// secondLevelDirs snapshots the <family>/<version> directories already
// present under dir — the units the non-clobber rule protects.
func secondLevelDirs(dir string) map[string]bool {
	existing := map[string]bool{}
	families, err := os.ReadDir(dir)
	if err != nil {
		return existing
	}
	for _, family := range families {
		if !family.IsDir() {
			continue
		}
		versions, verr := os.ReadDir(filepath.Join(dir, family.Name()))
		if verr != nil {
			continue
		}
		for _, version := range versions {
			if version.IsDir() {
				existing[family.Name()+"/"+version.Name()] = true
			}
		}
	}
	return existing
}
