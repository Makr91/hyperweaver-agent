package server

// Archive create/extract (zoneweaver's file_archive_create /
// file_archive_extract, task-queued): stdlib zip/tar/gzip instead of the
// base's shell tar. Creation formats: zip, tar, tar.gz (Go's bzip2 is
// decompress-only); extraction adds tar.bz2 and bare .gz.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

type archiveCreateMetadata struct {
	Sources     []string `json:"sources"`
	ArchivePath string   `json:"archive_path"`
	Format      string   `json:"format"`
}

func (s *Server) archiveGate(w http.ResponseWriter) bool {
	if !s.cfg.FileBrowser.Archive.Enabled {
		taskError(w, http.StatusServiceUnavailable, "Archive operations are disabled")
		return false
	}
	return true
}

// archiveCreateResponse is POST /filesystem/archive/create's 202 answer.
type archiveCreateResponse struct {
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	TaskID      string   `json:"task_id"`
	Sources     []string `json:"sources"`
	ArchivePath string   `json:"archive_path"`
	Format      string   `json:"format"`
}

// handleCreateArchive serves POST /filesystem/archive/create → 202 task.
//
//	@Summary		Create an archive (task)
//	@Description	Minimum role: operator. {sources[], archive_path, format} → 202 file_archive_create task. format must sit in file_browser.archive.supported_formats — this agent CREATES zip, tar, and tar.gz (Go's bzip2 is decompress-only; the base's shell tar also spoke tar.bz2). Entries are rooted at each source's basename. An archive landing over max_archive_size_mb is deleted and the task fails. Gated by file_browser.archive.enabled.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	archiveCreateMetadata	true	"Archive creation request"
//	@Success		202	{object}	archiveCreateResponse	"Archive creation task created ({success, message, task_id, sources, archive_path, format})"
//	@Failure		400	"Missing fields or unsupported format"
//	@Failure		403	"Path forbidden"
//	@Failure		503	"File browser or archive operations disabled"
//	@Router			/filesystem/archive/create [post]
func (s *Server) handleCreateArchive(w http.ResponseWriter, r *http.Request) {
	if !s.archiveGate(w) {
		return
	}
	var body archiveCreateMetadata
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if len(body.Sources) == 0 {
		taskError(w, http.StatusBadRequest, "sources array is required and must not be empty")
		return
	}
	if body.ArchivePath == "" || body.Format == "" {
		taskError(w, http.StatusBadRequest, "archive_path and format are required")
		return
	}
	supported := false
	for _, format := range s.cfg.FileBrowser.Archive.SupportedFormats {
		if format == body.Format {
			supported = true
			break
		}
	}
	if !supported {
		taskError(w, http.StatusBadRequest, "Unsupported archive format: "+body.Format+
			" (file_browser.archive.supported_formats)")
		return
	}
	for _, source := range body.Sources {
		if _, err := s.validateBrowsePath(source); err != nil {
			writeBrowseError(w, err, "Failed to create archive task")
			return
		}
	}
	if _, err := s.validateBrowsePath(body.ArchivePath); err != nil {
		writeBrowseError(w, err, "Failed to create archive task")
		return
	}
	task, err := s.queueFilesystemTask(r, opFileArchiveCreate, tasks.PriorityLow, &body)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create archive task")
		return
	}
	writeJSONStatus(w, http.StatusAccepted, archiveCreateResponse{
		Success:     true,
		Message:     fmt.Sprintf("Archive creation task created for %d items", len(body.Sources)),
		TaskID:      task.ID,
		Sources:     body.Sources,
		ArchivePath: body.ArchivePath,
		Format:      body.Format,
	})
}

func (s *Server) archiveCreateTask(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if !s.cfg.FileBrowser.Archive.Enabled {
		return errors.New("archive operations are disabled")
	}
	var meta archiveCreateMetadata
	if len(task.Metadata) == 0 {
		return errors.New("archive task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return err
	}
	destination, err := s.validateBrowsePath(meta.ArchivePath)
	if err != nil {
		return err
	}
	sources := make([]string, 0, len(meta.Sources))
	for _, source := range meta.Sources {
		normalized, verr := s.validateBrowsePath(source)
		if verr != nil {
			return verr
		}
		sources = append(sources, normalized)
	}

	out.Write("stdout", fmt.Sprintf("Creating %s archive %s from %d source(s)\n",
		meta.Format, destination, len(sources)))
	switch meta.Format {
	case "zip":
		err = createZipArchive(ctx, sources, destination)
	case "tar":
		err = createTarArchive(ctx, sources, destination, false)
	case "tar.gz":
		err = createTarArchive(ctx, sources, destination, true)
	default:
		return errors.New("unsupported archive format: " + meta.Format)
	}
	if err != nil {
		_ = os.Remove(destination)
		return err
	}

	info, serr := os.Stat(filepath.Clean(destination))
	if serr != nil {
		return serr
	}
	limit := int64(s.cfg.FileBrowser.Archive.MaxArchiveSizeMB) * 1024 * 1024
	if info.Size() > limit {
		_ = os.Remove(destination)
		return fmt.Errorf("archive size %dMB exceeds limit of %dMB — deleted",
			info.Size()/1024/1024, s.cfg.FileBrowser.Archive.MaxArchiveSizeMB)
	}
	out.Write("stdout", fmt.Sprintf("Archive created (%d bytes)\n", info.Size()))
	return nil
}

// archiveEntries walks each source, calling add with the entry path and its
// basename-rooted archive name (forward slashes).
func archiveEntries(ctx context.Context, sources []string, add func(path, name string, info os.FileInfo) error) error {
	for _, source := range sources {
		root := filepath.Dir(source)
		err := filepath.WalkDir(source, func(entry string, d os.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !d.IsDir() && !d.Type().IsRegular() {
				return nil // symlinks and specials are skipped
			}
			rel, rerr := filepath.Rel(root, entry)
			if rerr != nil {
				return rerr
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			return add(entry, filepath.ToSlash(rel), info)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// writeArchiveFile streams an archive build through the ONE write path
// (safepath.WriteFileFrom over a pipe): the temp-beside-target + rename
// discipline holds, so a failed build never leaves a partial archive.
func writeArchiveFile(destination string, build func(io.Writer) error) error {
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, werr := safepath.WriteFileFrom(destination, reader, 0o600)
		_ = reader.CloseWithError(werr)
		done <- werr
	}()
	buildErr := build(writer)
	_ = writer.CloseWithError(buildErr)
	writeErr := <-done
	if buildErr != nil {
		return buildErr
	}
	return writeErr
}

func createZipArchive(ctx context.Context, sources []string, destination string) error {
	return writeArchiveFile(destination, func(sink io.Writer) error {
		writer := zip.NewWriter(sink)
		err := archiveEntries(ctx, sources, func(path, name string, info os.FileInfo) error {
			header, herr := zip.FileInfoHeader(info)
			if herr != nil {
				return herr
			}
			header.Name = name
			if info.IsDir() {
				header.Name += "/"
			} else {
				header.Method = zip.Deflate
			}
			entry, werr := writer.CreateHeader(header)
			if werr != nil {
				return werr
			}
			if info.IsDir() {
				return nil
			}
			in, oerr := os.Open(filepath.Clean(path))
			if oerr != nil {
				return oerr
			}
			cerr := copyChunks(ctx, entry, in)
			if xerr := in.Close(); cerr == nil {
				cerr = xerr
			}
			return cerr
		})
		if werr := writer.Close(); err == nil {
			err = werr
		}
		return err
	})
}

func createTarArchive(ctx context.Context, sources []string, destination string, gzipped bool) error {
	return writeArchiveFile(destination, func(sink io.Writer) error {
		target := sink
		var gz *gzip.Writer
		if gzipped {
			gz = gzip.NewWriter(sink)
			target = gz
		}
		writer := tar.NewWriter(target)
		err := archiveEntries(ctx, sources, func(path, name string, info os.FileInfo) error {
			header, herr := tar.FileInfoHeader(info, "")
			if herr != nil {
				return herr
			}
			header.Name = name
			if info.IsDir() {
				header.Name += "/"
			}
			if werr := writer.WriteHeader(header); werr != nil {
				return werr
			}
			if info.IsDir() {
				return nil
			}
			in, oerr := os.Open(filepath.Clean(path))
			if oerr != nil {
				return oerr
			}
			cerr := copyChunks(ctx, writer, in)
			if xerr := in.Close(); cerr == nil {
				cerr = xerr
			}
			return cerr
		})
		if werr := writer.Close(); err == nil {
			err = werr
		}
		if gz != nil {
			if werr := gz.Close(); err == nil {
				err = werr
			}
		}
		return err
	})
}
