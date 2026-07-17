package provisioner

// Host-to-host share, the export half (design §7, ruled 2026-07-16): one
// version → ONE tar.gz, REGISTRY-SHAPED (<name>/<version>/… inside the tar —
// the artifact contract's own layout, so the receiving side's ordinary
// import consumes it), plus the sha256 OF THE ARCHIVE (whole-file only, no
// per-file manifests) in the task output AND a `<file>.sha256` sidecar (the
// catalog's sidecar convention). The import half is the multipart
// import-upload endpoint feeding the ordinary provisioner_import task.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// OpExport is the provisioner-export task operation (CategorySystem — it
// reads the shared registry tree while imports may write it).
const OpExport = "provisioner_export"

// exportsDirName holds built archives under the registry root. The scan
// never mistakes it for a family: it carries no collection manifest.
const exportsDirName = "exports"

// ExportMetadata is the provisioner_export task's metadata document.
type ExportMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// exportVersion executes provisioner_export: build the archive + sidecar and
// report both paths and the archive hash in the task output.
func (e *executors) exportVersion(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if task.Metadata == nil {
		return errors.New("export task has no metadata")
	}
	var meta ExportMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse export metadata: %w", err)
	}
	version, err := e.registry.GetVersion(meta.Name, meta.Version)
	if err != nil {
		return err
	}

	destDir := filepath.Join(e.registry.Dir(), exportsDirName)
	if merr := os.MkdirAll(destDir, 0o750); merr != nil {
		return merr
	}
	archive := filepath.Join(destDir, meta.Name+"-"+version.Version+".tar.gz")
	out.Write("stdout", "Building "+archive+"\n")
	sum, bytes, err := BuildVersionArchive(ctx, version.Root, meta.Name, version.Dir, archive)
	if err != nil {
		return err
	}
	sidecar := archive + ".sha256"
	if werr := safepath.WriteFile(sidecar,
		[]byte(sum+"  "+filepath.Base(archive)+"\n"), 0o644); werr != nil {
		return werr
	}
	out.Write("stdout", fmt.Sprintf("Archive: %s (%d bytes)\n", archive, bytes))
	out.Write("stdout", "sha256: "+sum+"\n")
	out.Write("stdout", "Sidecar: "+sidecar+"\n")
	return nil
}

// BuildVersionArchive streams one version directory into a registry-shaped
// tar.gz at dest (every entry prefixed <family>/<versionDir>/), hashing the
// ARCHIVE BYTES as they land — the whole-file sha256 the share contract
// pins. Irregular entries (symlinks, devices) never enter the archive. The
// walk and every file open ride a root-scoped handle, so a path component
// swapped for a symlink mid-walk can never pull outside the version tree
// (TOCTOU).
func BuildVersionArchive(ctx context.Context, root, family, versionDir, dest string) (sum string, size int64, err error) {
	cleanRoot, err := safepath.CleanAbs(root)
	if err != nil {
		return "", 0, err
	}
	rootHandle, err := os.OpenRoot(cleanRoot)
	if err != nil {
		return "", 0, err
	}
	// The writer goroutine finishes before WriteFileFrom returns (the pipe
	// closes only when the walk is done), so the close never races it.
	defer func() {
		if cerr := rootHandle.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	pr, pw := io.Pipe()
	go func() {
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		walkErr := fs.WalkDir(rootHandle.FS(), ".", func(path string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// fs paths are slash-separated already.
			name := family + "/" + versionDir
			if path != "." {
				name += "/" + path
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			switch {
			case d.IsDir():
				return tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeDir,
					Name:     name + "/",
					Mode:     int64(info.Mode().Perm()),
					ModTime:  info.ModTime(),
				})
			case info.Mode().IsRegular():
				if herr := tw.WriteHeader(&tar.Header{
					Typeflag: tar.TypeReg,
					Name:     name,
					Mode:     int64(info.Mode().Perm()),
					Size:     info.Size(),
					ModTime:  info.ModTime(),
				}); herr != nil {
					return herr
				}
				f, oerr := rootHandle.Open(path)
				if oerr != nil {
					return oerr
				}
				_, cerr := io.Copy(tw, f)
				if clerr := f.Close(); cerr == nil {
					cerr = clerr
				}
				return cerr
			default:
				// Symlinks and specials never enter a share archive (the
				// extract side would skip them anyway).
				return nil
			}
		})
		if walkErr == nil {
			walkErr = tw.Close()
		} else {
			_ = tw.Close()
		}
		if gerr := gz.Close(); walkErr == nil {
			walkErr = gerr
		}
		pw.CloseWithError(walkErr)
	}()

	hasher := sha256.New()
	size, err = safepath.WriteFileFrom(dest, io.TeeReader(pr, hasher), 0o644)
	if err != nil {
		return "", size, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// IsArchiveName exposes the package's archive-name rule to the HTTP layer
// (the import-upload handler validates the multipart filename with it).
func IsArchiveName(name string) bool {
	return isArchive(name)
}
