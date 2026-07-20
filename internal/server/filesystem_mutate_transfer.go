package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// handleDownloadFile serves GET /filesystem/download — streams one file as an
// attachment (directories are refused: "use archive creation instead").
//
//	@Summary		Download a file
//	@Description	Minimum role: operator. Streams the file as an attachment (range requests honored); directories are refused — archive them instead.
//	@Tags			File System
//	@Produce		octet-stream
//	@Param			path	query	string	true	"File path to download"
//	@Success		200	{file}		binary	"The file"
//	@Failure		400	"Missing path, or path is a directory"
//	@Failure		403	"Path forbidden"
//	@Failure		404	"File not found"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/download [get]
func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		taskError(w, http.StatusBadRequest, "path parameter is required")
		return
	}
	normalized, err := s.validateBrowsePath(path)
	if err != nil {
		writeBrowseError(w, err, "Failed to download file")
		return
	}
	file, err := os.Open(filepath.Clean(normalized))
	if err != nil {
		writeBrowseError(w, err, "Failed to download file")
		return
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil {
		writeBrowseError(w, err, "Failed to download file")
		return
	}
	if info.IsDir() {
		taskError(w, http.StatusBadRequest, "Cannot download directory - use archive creation instead")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(normalized)+`"`)
	http.ServeContent(w, r, filepath.Base(normalized), info.ModTime(), file)
}

// uploadedFileInfo is the created file's summary in an upload's answer.
type uploadedFileInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	IsDirectory bool   `json:"isDirectory"`
	Size        int64  `json:"size"`
}

// uploadFileResponse is POST /filesystem/upload's answer.
type uploadFileResponse struct {
	Success bool             `json:"success"`
	Message string           `json:"message"`
	File    uploadedFileInfo `json:"file"`
}

// handleUploadFile serves POST /filesystem/upload — the base's uploadFile:
// multipart with the metadata fields BEFORE the file part (uploadPath,
// overwrite, mode), streamed to the destination through a temp file. Body
// bounded by file_browser.upload_size_limit_gb.
//
//	@Summary		Upload a file
//	@Description	Minimum role: operator. multipart/form-data with the metadata fields BEFORE the file part (multipart streams in order — the base's multer has the same rule): uploadPath (required), overwrite ("true"), mode (octal string). The filename is sanitized to [a-zA-Z0-9._-]; the body is capped by file_browser.upload_size_limit_gb and streams to the destination through a temp file.
//	@Tags			File System
//	@Accept			mpfd
//	@Produce		json
//	@Param			uploadPath	formData	string	true	"Destination directory (must precede the file part)"
//	@Param			overwrite	formData	string	false	"Set to true to overwrite an existing file"
//	@Param			mode		formData	string	false	"Octal permission string, e.g. 644"
//	@Param			file		formData	file	true	"The file to upload"
//	@Success		201	{object}	uploadFileResponse	"File uploaded ({success, message, file})"
//	@Failure		400	"Not multipart, no file part, uploadPath missing or after the file part"
//	@Failure		403	"Path forbidden"
//	@Failure		409	"File already exists (set overwrite)"
//	@Failure		413	"Body exceeds file_browser.upload_size_limit_gb"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/upload [post]
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.FileBrowser.UploadSizeLimitGB)<<30)
	reader, err := r.MultipartReader()
	if err != nil {
		taskError(w, http.StatusBadRequest, "Request must be multipart/form-data")
		return
	}

	uploadPath := ""
	overwrite := false
	mode := ""
	for {
		part, perr := reader.NextPart()
		if errors.Is(perr, io.EOF) {
			taskError(w, http.StatusBadRequest, "No file uploaded")
			return
		}
		if perr != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(perr, &tooLarge) {
				taskError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
					"Upload exceeds file_browser.upload_size_limit_gb (%d GiB)", s.cfg.FileBrowser.UploadSizeLimitGB))
				return
			}
			taskError(w, http.StatusBadRequest, "Malformed multipart body")
			return
		}

		if part.FormName() != "file" {
			value, verr := io.ReadAll(io.LimitReader(part, 4096))
			_ = part.Close()
			if verr != nil {
				taskError(w, http.StatusBadRequest, "Malformed multipart field")
				return
			}
			switch part.FormName() {
			case "uploadPath":
				uploadPath = string(value)
			case "overwrite":
				overwrite = string(value) == "true"
			case "mode":
				mode = string(value)
			}
			continue
		}

		// The file part: everything needed must already be known (multipart
		// streams in order — the base's multer has the same rule).
		if uploadPath == "" {
			_ = part.Close()
			taskError(w, http.StatusBadRequest, "uploadPath field must precede the file part")
			return
		}
		filename := sanitizeFileName(filepath.Base(part.FileName()))
		if filename == "" || filename == "." {
			_ = part.Close()
			taskError(w, http.StatusBadRequest, "File part carries no usable filename")
			return
		}
		normalized, verr := s.validateBrowsePath(filepath.Join(filepath.FromSlash(uploadPath), filename))
		if verr != nil {
			_ = part.Close()
			writeBrowseError(w, verr, "Failed to upload file")
			return
		}
		if !overwrite {
			if _, serr := os.Stat(normalized); serr == nil {
				_ = part.Close()
				taskError(w, http.StatusConflict, "File already exists: "+filename+" (set overwrite)")
				return
			}
		}

		temp := normalized + ".upload"
		size, werr := safepath.WriteFileFrom(temp, part, 0o600)
		_ = part.Close()
		if werr != nil {
			_ = os.Remove(temp)
			var tooLarge *http.MaxBytesError
			if errors.As(werr, &tooLarge) {
				taskError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
					"Upload exceeds file_browser.upload_size_limit_gb (%d GiB)", s.cfg.FileBrowser.UploadSizeLimitGB))
				return
			}
			writeBrowseError(w, werr, "Failed to upload file")
			return
		}
		if rerr := os.Rename(temp, normalized); rerr != nil {
			_ = os.Remove(temp)
			writeBrowseError(w, rerr, "Failed to upload file")
			return
		}
		if mode != "" {
			if parsed, merr := parseOctalMode(mode); merr == nil {
				if cerr := applyMode(normalized, parsed, false); cerr != nil {
					slog.Warn("set permissions on upload", "path", normalized, "error", cerr)
				}
			} else {
				slog.Warn("upload mode field unparseable", "mode", mode, "error", merr)
			}
		}

		slog.Info("file uploaded", "path", normalized, "size", size,
			"by", auth.FromContext(r.Context()).Name)
		writeJSONStatus(w, http.StatusCreated, uploadFileResponse{
			Success: true,
			Message: "File '" + filename + "' uploaded successfully",
			File: uploadedFileInfo{
				Name:        filename,
				Path:        filepath.ToSlash(normalized),
				IsDirectory: false,
				Size:        size,
			},
		})
		return
	}
}
