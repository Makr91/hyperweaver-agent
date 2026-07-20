package server

// Archive create/extract (zoneweaver's file_archive_create /
// file_archive_extract, task-queued): stdlib zip/tar/gzip instead of the
// base's shell tar. Creation formats: zip, tar, tar.gz (Go's bzip2 is
// decompress-only); extraction adds tar.bz2 and bare .gz.

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

type archiveCreateMetadata struct {
	Sources     []string `json:"sources"`
	ArchivePath string   `json:"archive_path"`
	Format      string   `json:"format"`
}

type archiveExtractMetadata struct {
	ArchivePath string `json:"archive_path"`
	ExtractPath string `json:"extract_path"`
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

// archiveExtractResponse is POST /filesystem/archive/extract's 202 answer.
type archiveExtractResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	TaskID      string `json:"task_id"`
	ArchivePath string `json:"archive_path"`
	ExtractPath string `json:"extract_path"`
}

// handleExtractArchive serves POST /filesystem/archive/extract → 202 task.
//
//	@Summary		Extract an archive (task)
//	@Description	Minimum role: operator. {archive_path, extract_path} → 202 file_archive_extract task. Format by extension: .zip, .tar, .tar.gz, .tar.bz2, bare .gz. Entries escaping the extraction directory are rejected (zip-slip guard); links and specials are skipped, never materialized. Gated by file_browser.archive.enabled.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	archiveExtractMetadata	true	"Archive extraction request"
//	@Success		202	{object}	archiveExtractResponse	"Extraction task created ({success, message, task_id, archive_path, extract_path})"
//	@Failure		400	"Missing fields"
//	@Failure		403	"Path forbidden"
//	@Failure		503	"File browser or archive operations disabled"
//	@Router			/filesystem/archive/extract [post]
func (s *Server) handleExtractArchive(w http.ResponseWriter, r *http.Request) {
	if !s.archiveGate(w) {
		return
	}
	var body archiveExtractMetadata
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.ArchivePath == "" || body.ExtractPath == "" {
		taskError(w, http.StatusBadRequest, "archive_path and extract_path are required")
		return
	}
	if _, err := s.validateBrowsePath(body.ArchivePath); err != nil {
		writeBrowseError(w, err, "Failed to create extraction task")
		return
	}
	if _, err := s.validateBrowsePath(body.ExtractPath); err != nil {
		writeBrowseError(w, err, "Failed to create extraction task")
		return
	}
	task, err := s.queueFilesystemTask(r, opFileArchiveExtract, tasks.PriorityLow, &body)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to create extraction task")
		return
	}
	writeJSONStatus(w, http.StatusAccepted, archiveExtractResponse{
		Success:     true,
		Message:     "Archive extraction task created for '" + filepath.Base(body.ArchivePath) + "'",
		TaskID:      task.ID,
		ArchivePath: body.ArchivePath,
		ExtractPath: body.ExtractPath,
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

func (s *Server) archiveExtractTask(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if !s.cfg.FileBrowser.Archive.Enabled {
		return errors.New("archive operations are disabled")
	}
	var meta archiveExtractMetadata
	if len(task.Metadata) == 0 {
		return errors.New("archive task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return err
	}
	archivePath, err := s.validateBrowsePath(meta.ArchivePath)
	if err != nil {
		return err
	}
	extractPath, err := s.validateBrowsePath(meta.ExtractPath)
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(extractPath, 0o750); merr != nil {
		return merr
	}

	lower := strings.ToLower(archivePath)
	out.Write("stdout", "Extracting "+archivePath+" -> "+extractPath+"\n")
	var count int
	switch {
	case strings.HasSuffix(lower, ".zip"):
		count, err = extractZip(ctx, archivePath, extractPath)
	case strings.HasSuffix(lower, ".tar.gz"):
		count, err = extractTarStream(ctx, archivePath, extractPath, "gzip")
	case strings.HasSuffix(lower, ".tar.bz2"):
		count, err = extractTarStream(ctx, archivePath, extractPath, "bzip2")
	case strings.HasSuffix(lower, ".tar"):
		count, err = extractTarStream(ctx, archivePath, extractPath, "")
	case strings.HasSuffix(lower, ".gz"):
		count, err = extractGzipFile(ctx, archivePath, extractPath)
	default:
		return errors.New("unsupported archive format: " + filepath.Ext(archivePath))
	}
	if err != nil {
		return err
	}
	out.Write("stdout", fmt.Sprintf("Extraction complete: %d entrie(s)\n", count))
	return nil
}

// extractTarget contains an entry name inside the extraction root (the
// zip-slip guard: rejected instead of written outside).
func extractTarget(extractPath, name string) (string, error) {
	target := filepath.Join(extractPath, filepath.FromSlash(name))
	if !pathWithin(extractPath, target) && !sameBrowsePath(target, extractPath) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	return target, nil
}

// ctxReader cancels a read stream with its context — extraction stays
// cancellable while the write rides safepath.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func writeExtractedFile(ctx context.Context, target string, mode os.FileMode, src io.Reader) error {
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return merr
	}
	_, err := safepath.WriteFileFrom(target, ctxReader{ctx: ctx, r: src}, mode.Perm()|0o200)
	return err
}

func extractZip(ctx context.Context, archivePath, extractPath string) (int, error) {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = reader.Close()
	}()
	count := 0
	for _, entry := range reader.File {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		target, terr := extractTarget(extractPath, entry.Name)
		if terr != nil {
			return count, terr
		}
		if entry.FileInfo().IsDir() {
			if merr := os.MkdirAll(target, 0o750); merr != nil {
				return count, merr
			}
			count++
			continue
		}
		src, oerr := entry.Open()
		if oerr != nil {
			return count, oerr
		}
		werr := writeExtractedFile(ctx, target, entry.Mode(), src)
		_ = src.Close()
		if werr != nil {
			return count, werr
		}
		count++
	}
	return count, nil
}

func extractTarStream(ctx context.Context, archivePath, extractPath, compression string) (int, error) {
	file, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = file.Close()
	}()
	var stream io.Reader = file
	switch compression {
	case "gzip":
		gz, gerr := gzip.NewReader(file)
		if gerr != nil {
			return 0, gerr
		}
		defer func() {
			_ = gz.Close()
		}()
		stream = gz
	case "bzip2":
		stream = bzip2.NewReader(file)
	}
	reader := tar.NewReader(stream)
	count := 0
	for {
		if ctx.Err() != nil {
			return count, ctx.Err()
		}
		header, herr := reader.Next()
		if errors.Is(herr, io.EOF) {
			return count, nil
		}
		if herr != nil {
			return count, herr
		}
		target, terr := extractTarget(extractPath, header.Name)
		if terr != nil {
			return count, terr
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if merr := os.MkdirAll(target, 0o750); merr != nil {
				return count, merr
			}
			count++
		case tar.TypeReg:
			if werr := writeExtractedFile(ctx, target, header.FileInfo().Mode(), reader); werr != nil {
				return count, werr
			}
			count++
		default:
			// Links and specials are skipped — never materialized.
		}
	}
}

func extractGzipFile(ctx context.Context, archivePath, extractPath string) (int, error) {
	file, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = file.Close()
	}()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = gz.Close()
	}()
	name := strings.TrimSuffix(filepath.Base(archivePath), filepath.Ext(archivePath))
	target, terr := extractTarget(extractPath, name)
	if terr != nil {
		return 0, terr
	}
	if werr := writeExtractedFile(ctx, target, 0o600, gz); werr != nil {
		return 0, werr
	}
	return 1, nil
}
