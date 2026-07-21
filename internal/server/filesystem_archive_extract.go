package server

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

type archiveExtractMetadata struct {
	ArchivePath string `json:"archive_path"`
	ExtractPath string `json:"extract_path"`
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
// zip-slip guard: rejected instead of written outside). filepath.IsLocal
// refuses absolute, drive-lettered, reserved, and ..-escaping names
// lexically; the pathWithin check then confirms containment of the joined
// result.
func extractTarget(extractPath, name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." {
		return extractPath, nil
	}
	if !filepath.IsLocal(clean) {
		return "", fmt.Errorf("archive entry %q escapes the extraction directory", name)
	}
	target := filepath.Join(extractPath, clean)
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
