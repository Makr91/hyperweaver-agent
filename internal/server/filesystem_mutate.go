package server

// The /filesystem mutate family — zoneweaver's FileSystemController mutation
// surface ported 1:1 (Mark's go 2026-07-12): create folder, text content
// read/write, upload/download, rename, delete, permissions (move/copy and
// archives are task-queued — filesystem_tasks.go / filesystem_archive.go).
// Native Go file operations replace the base's pfexec shell-outs. uid/gid
// ownership applies on Unix hosts only — a Windows host answers an honest
// 400, never a silent no-op. Every path passes the same validateBrowsePath
// bounds the browse endpoint enforces; the whole family rides the
// file-browser gate (503 when disabled) and the central policy's operator
// role (the /filesystem prefix rule).

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// unsafeNameCharacters is the base's rename/upload sanitizer: anything
// outside [a-zA-Z0-9._-] becomes an underscore.
var unsafeNameCharacters = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeFileName applies the base's filename rule.
func sanitizeFileName(name string) string {
	return unsafeNameCharacters.ReplaceAllString(name, "_")
}

// writeBrowseError maps a filesystem error onto the base's status vocabulary:
// 403 forbidden, 404 missing, 500 {error, details} otherwise. Every refusal
// ALSO logs (Mark's go 2026-07-17: a permission denial that lives only in the
// response body makes agent.log blind to the whole failure class — the OS
// error text carries the path, so one line here covers every mutate handler).
func writeBrowseError(w http.ResponseWriter, err error, message string) {
	slog.Warn("filesystem operation refused", "context", message, "error", err)
	switch {
	case errors.Is(err, errBrowseForbidden):
		taskError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, os.ErrNotExist):
		taskError(w, http.StatusNotFound, "Item not found")
	default:
		writeJSONStatus(w, http.StatusInternalServerError,
			map[string]any{"error": message, "details": err.Error()})
	}
}

// browseItem validates and stats one path into the wire item shape (the
// base's getItemInfo, reusing the listing's per-entry builder).
func (s *Server) browseItem(path string) (fileSystemItem, error) {
	normalized, err := s.validateBrowsePath(path)
	if err != nil {
		return fileSystemItem{}, err
	}
	info, err := os.Stat(filepath.Clean(normalized))
	if err != nil {
		return fileSystemItem{}, err
	}
	return browseItemInfo(normalized, info), nil
}

// applyOwnership sets uid/gid on a path (chown -R when recursive) — Unix
// hosts only; Windows has no analog and answers an error the caller maps.
// The recursion is root-scoped (os.Root): no symlink escape, no TOCTOU —
// gosec G122's exact recommendation.
func applyOwnership(path string, uid, gid *int, recursive bool) error {
	if runtime.GOOS == "windows" {
		return errors.New("uid/gid ownership has no analog on a Windows host")
	}
	owner, group := -1, -1
	if uid != nil {
		owner = *uid
	}
	if gid != nil {
		group = *gid
	}
	if err := os.Chown(path, owner, group); err != nil || !recursive {
		return err
	}
	info, err := os.Stat(filepath.Clean(path))
	if err != nil || !info.IsDir() {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()
	return fs.WalkDir(root.FS(), ".", func(rel string, _ fs.DirEntry, werr error) error {
		if werr != nil || rel == "." {
			return werr
		}
		return root.Chown(rel, owner, group)
	})
}

// applyMode chmods a path (chmod -R when recursive, root-scoped like
// applyOwnership). On Windows Go's chmod only toggles the read-only
// attribute — the honest platform reality.
func applyMode(path string, mode os.FileMode, recursive bool) error {
	if err := os.Chmod(path, mode); err != nil || !recursive {
		return err
	}
	info, err := os.Stat(filepath.Clean(path))
	if err != nil || !info.IsDir() {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = root.Close()
	}()
	return fs.WalkDir(root.FS(), ".", func(rel string, _ fs.DirEntry, werr error) error {
		if werr != nil || rel == "." {
			return werr
		}
		return root.Chmod(rel, mode)
	})
}

// parseOctalMode reads the base's octal-string permission form ("644").
func parseOctalMode(raw string) (os.FileMode, error) {
	value, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("mode %q is not octal", raw)
	}
	return os.FileMode(value), nil
}

// createFolderRequest is POST /filesystem/folder's body.
type createFolderRequest struct {
	Path string `json:"path"`
	Name string `json:"name"`
	// Octal permission string, e.g. "755"
	Mode string `json:"mode"`
	UID  *int   `json:"uid"`
	GID  *int   `json:"gid"`
}

// createFolderResponse is POST /filesystem/folder's answer.
type createFolderResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message"`
	Item    fileSystemItem `json:"item"`
}

// handleCreateFolder serves POST /filesystem/folder — the base's createFolder:
// {path, name, mode?, uid?, gid?} → 201 with the new directory's item.
//
//	@Summary		Create a directory
//	@Description	Minimum role: operator. {path, name, mode?, uid?, gid?} — mode is octal ("755"); uid/gid apply on Unix hosts (failures narrate to the log, never block — the base's tolerance). Synchronous.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	createFolderRequest	true	"Parent path, folder name, and optional mode/uid/gid"
//	@Success		201	{object}	createFolderResponse	"Directory created ({success, message, item})"
//	@Failure		400	"Missing fields, bad mode, or directory already exists"
//	@Failure		403	"Path forbidden"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/folder [post]
func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	var body createFolderRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" || body.Name == "" {
		taskError(w, http.StatusBadRequest, "path and name are required")
		return
	}
	normalized, err := s.validateBrowsePath(filepath.Join(filepath.FromSlash(body.Path), body.Name))
	if err != nil {
		writeBrowseError(w, err, "Failed to create directory")
		return
	}
	if merr := os.Mkdir(normalized, 0o750); merr != nil {
		if errors.Is(merr, os.ErrExist) {
			taskError(w, http.StatusBadRequest, "Directory already exists")
			return
		}
		writeBrowseError(w, merr, "Failed to create directory")
		return
	}
	if body.Mode != "" {
		mode, perr := parseOctalMode(body.Mode)
		if perr != nil {
			taskError(w, http.StatusBadRequest, perr.Error())
			return
		}
		if cerr := applyMode(normalized, mode, false); cerr != nil {
			slog.Warn("set directory permissions", "path", normalized, "error", cerr)
		}
	}
	if body.UID != nil || body.GID != nil {
		if cerr := applyOwnership(normalized, body.UID, body.GID, false); cerr != nil {
			slog.Warn("set directory ownership", "path", normalized, "error", cerr)
		}
	}
	item, ierr := s.browseItem(normalized)
	if ierr != nil {
		writeBrowseError(w, ierr, "Failed to create directory")
		return
	}
	writeJSONStatus(w, http.StatusCreated, createFolderResponse{
		Success: true,
		Message: "Directory '" + body.Name + "' created successfully",
		Item:    item,
	})
}

// readFileContentResponse is GET /filesystem/content's answer.
type readFileContentResponse struct {
	Content   string         `json:"content"`
	FileInfo  fileSystemItem `json:"file_info"`
	Encoding  string         `json:"encoding"`
	SizeBytes int            `json:"size_bytes"`
}

// handleReadFileContent serves GET /filesystem/content — the base's readFile:
// text files only, bounded by security.max_edit_size_mb.
//
//	@Summary		Read text file content
//	@Description	Minimum role: operator. Text files only (the 8KB binary sample refuses binaries) bounded by security.max_edit_size_mb — the file-manager editor's read.
//	@Tags			File System
//	@Produce		json
//	@Param			path	query	string	true	"File path to read"
//	@Success		200	{object}	readFileContentResponse	"File content"
//	@Failure		400	"Binary file, over the edit limit, or a directory"
//	@Failure		403	"Path forbidden"
//	@Failure		404	"File not found"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/content [get]
func (s *Server) handleReadFileContent(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		taskError(w, http.StatusBadRequest, "path parameter is required")
		return
	}
	normalized, err := s.validateBrowsePath(path)
	if err != nil {
		writeBrowseError(w, err, "Failed to read file")
		return
	}
	info, err := os.Stat(filepath.Clean(normalized))
	if err != nil {
		writeBrowseError(w, err, "Failed to read file")
		return
	}
	if info.IsDir() {
		taskError(w, http.StatusBadRequest, "Cannot read directory as file")
		return
	}
	limit := int64(s.cfg.FileBrowser.Security.MaxEditSizeMB) * 1024 * 1024
	if info.Size() > limit {
		taskError(w, http.StatusBadRequest, fmt.Sprintf(
			"File size %dMB exceeds edit limit of %dMB",
			info.Size()/1024/1024, s.cfg.FileBrowser.Security.MaxEditSizeMB))
		return
	}
	if isBinarySample(normalized) {
		taskError(w, http.StatusBadRequest, "Cannot read binary file as text")
		return
	}
	content, err := os.ReadFile(filepath.Clean(normalized))
	if err != nil {
		writeBrowseError(w, err, "Failed to read file")
		return
	}
	writeJSON(w, readFileContentResponse{
		Content:   string(content),
		FileInfo:  browseItemInfo(normalized, info),
		Encoding:  "utf8",
		SizeBytes: len(content),
	})
}

// writeFileContentRequest is PUT /filesystem/content's body.
type writeFileContentRequest struct {
	Path    string  `json:"path"`
	Content *string `json:"content"`
	Backup  bool    `json:"backup"`
	// Octal permission string, e.g. "644"
	Mode string `json:"mode"`
	UID  *int   `json:"uid"`
	GID  *int   `json:"gid"`
}

// writeFileContentResponse is PUT /filesystem/content's answer.
type writeFileContentResponse struct {
	Success     bool           `json:"success"`
	Message     string         `json:"message"`
	FileInfo    fileSystemItem `json:"file_info"`
	ContentSize int            `json:"content_size"`
}

// handleWriteFileContent serves PUT /filesystem/content — the base's
// writeFile: {path, content, backup?, uid?, gid?, mode?}; backup copies the
// existing file to <path>.backup.<unix-ms> first (failure narrates, never
// blocks — the base's rule).
//
//	@Summary		Write text file content
//	@Description	Minimum role: operator. {path, content, backup?, uid?, gid?, mode?} bounded by security.max_edit_size_mb; backup copies the existing file to <path>.backup.<unix-ms> first (failure narrates, never blocks). Synchronous.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	writeFileContentRequest	true	"Path, content, and optional backup/mode/uid/gid"
//	@Success		200	{object}	writeFileContentResponse	"File written ({success, message, file_info, content_size})"
//	@Failure		400	"Missing fields, bad mode, or content over the edit limit"
//	@Failure		403	"Path forbidden"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/content [put]
func (s *Server) handleWriteFileContent(w http.ResponseWriter, r *http.Request) {
	var body writeFileContentRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" || body.Content == nil {
		taskError(w, http.StatusBadRequest, "path and content are required")
		return
	}
	limit := s.cfg.FileBrowser.Security.MaxEditSizeMB
	if len(*body.Content) > limit*1024*1024 {
		taskError(w, http.StatusBadRequest, fmt.Sprintf(
			"Content size %dMB exceeds edit limit of %dMB", len(*body.Content)/1024/1024, limit))
		return
	}
	normalized, err := s.validateBrowsePath(body.Path)
	if err != nil {
		writeBrowseError(w, err, "Failed to write file")
		return
	}
	if body.Backup {
		if original, oerr := os.ReadFile(filepath.Clean(normalized)); oerr == nil {
			backupPath := fmt.Sprintf("%s.backup.%d", normalized, time.Now().UnixMilli())
			if werr := safepath.WriteFile(backupPath, original, 0o600); werr != nil {
				slog.Warn("file backup before write failed", "path", normalized, "error", werr)
			}
		}
	}
	if _, werr := safepath.WriteFileFrom(normalized, strings.NewReader(*body.Content), 0o600); werr != nil {
		writeBrowseError(w, werr, "Failed to write file")
		return
	}
	if body.Mode != "" {
		mode, perr := parseOctalMode(body.Mode)
		if perr != nil {
			taskError(w, http.StatusBadRequest, perr.Error())
			return
		}
		if cerr := applyMode(normalized, mode, false); cerr != nil {
			slog.Warn("set file permissions after write", "path", normalized, "error", cerr)
		}
	}
	if body.UID != nil || body.GID != nil {
		if cerr := applyOwnership(normalized, body.UID, body.GID, false); cerr != nil {
			slog.Warn("set file ownership after write", "path", normalized, "error", cerr)
		}
	}
	item, ierr := s.browseItem(normalized)
	if ierr != nil {
		writeBrowseError(w, ierr, "Failed to write file")
		return
	}
	message := "File written successfully"
	if body.Backup {
		message += " (backup created)"
	}
	writeJSON(w, writeFileContentResponse{
		Success:     true,
		Message:     message,
		FileInfo:    item,
		ContentSize: len(*body.Content),
	})
}

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

// renameItemRequest is PATCH /filesystem/rename's body.
type renameItemRequest struct {
	Path    string `json:"path"`
	NewName string `json:"new_name"`
}

// renameItemResponse is PATCH /filesystem/rename's answer.
type renameItemResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message"`
	Item    fileSystemItem `json:"item"`
	OldPath string         `json:"old_path"`
	NewPath string         `json:"new_path"`
}

// handleRenameItem serves PATCH /filesystem/rename — the base's renameItem:
// {path, new_name}, the name sanitized to [a-zA-Z0-9._-], same directory.
//
//	@Summary		Rename an item
//	@Description	Minimum role: operator. {path, new_name} — the new name is sanitized to [a-zA-Z0-9._-] and stays in the same directory. Synchronous.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	renameItemRequest	true	"Path and new_name"
//	@Success		200	{object}	renameItemResponse	"Item renamed ({success, message, item, old_path, new_path})"
//	@Failure		400	"Missing fields"
//	@Failure		403	"Path forbidden"
//	@Failure		404	"Item not found"
//	@Failure		409	"Target name already exists"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/rename [patch]
func (s *Server) handleRenameItem(w http.ResponseWriter, r *http.Request) {
	var body renameItemRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" || body.NewName == "" {
		taskError(w, http.StatusBadRequest, "path and new_name are required")
		return
	}
	sanitized := sanitizeFileName(body.NewName)
	normalized, err := s.validateBrowsePath(body.Path)
	if err != nil {
		writeBrowseError(w, err, "Failed to rename item")
		return
	}
	target, err := s.validateBrowsePath(filepath.Join(filepath.Dir(normalized), sanitized))
	if err != nil {
		writeBrowseError(w, err, "Failed to rename item")
		return
	}
	if _, serr := os.Stat(target); serr == nil {
		taskError(w, http.StatusConflict, "Target name already exists")
		return
	}
	if rerr := os.Rename(normalized, target); rerr != nil {
		writeBrowseError(w, rerr, "Failed to rename item")
		return
	}
	item, ierr := s.browseItem(target)
	if ierr != nil {
		writeBrowseError(w, ierr, "Failed to rename item")
		return
	}
	writeJSON(w, renameItemResponse{
		Success: true,
		Message: "Item renamed to '" + sanitized + "' successfully",
		Item:    item,
		OldPath: filepath.ToSlash(normalized),
		NewPath: filepath.ToSlash(target),
	})
}

// deleteFileItemRequest is DELETE /filesystem's body.
type deleteFileItemRequest struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
	Force     bool   `json:"force"`
}

// deletedItemInfo describes the removed item in a delete's answer.
type deletedItemInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	IsDirectory bool   `json:"isDirectory"`
	// Byte size, files only (absent for directories)
	Size *int64 `json:"size,omitempty"`
}

// deleteFileItemResponse is DELETE /filesystem's answer.
type deleteFileItemResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	// Absent on the already-absent (force) branch
	DeletedItem *deletedItemInfo `json:"deleted_item,omitempty"`
}

// handleDeleteFileItem serves DELETE /filesystem — the base's deleteFileItem:
// body {path, recursive?, force?}. Directories need recursive (a non-empty
// directory without it fails honestly); force tolerates already-gone paths.
//
//	@Summary		Delete a file or directory
//	@Description	Minimum role: operator. The base's deleteFileItem: directories need recursive (a non-empty directory without it fails honestly); force tolerates already-absent paths. Synchronous.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	deleteFileItemRequest	true	"Path, and optional recursive/force"
//	@Success		200	{object}	deleteFileItemResponse	"Item deleted ({success, message, deleted_item})"
//	@Failure		400	"Missing path or invalid body"
//	@Failure		403	"Path forbidden"
//	@Failure		404	"Item not found"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem [delete]
func (s *Server) handleDeleteFileItem(w http.ResponseWriter, r *http.Request) {
	var body deleteFileItemRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" {
		taskError(w, http.StatusBadRequest, "path is required")
		return
	}
	normalized, err := s.validateBrowsePath(body.Path)
	if err != nil {
		writeBrowseError(w, err, "Failed to delete item")
		return
	}
	info, serr := os.Stat(filepath.Clean(normalized))
	if serr != nil {
		if body.Force && errors.Is(serr, os.ErrNotExist) {
			writeJSON(w, deleteFileItemResponse{
				Success: true,
				Message: "Item already absent",
			})
			return
		}
		writeBrowseError(w, serr, "Failed to delete item")
		return
	}
	deletedItem := deletedItemInfo{
		Name:        filepath.Base(normalized),
		Path:        filepath.ToSlash(normalized),
		IsDirectory: info.IsDir(),
	}
	if !info.IsDir() {
		size := info.Size()
		deletedItem.Size = &size
	}

	var derr error
	if info.IsDir() && body.Recursive {
		derr = os.RemoveAll(normalized)
	} else {
		derr = os.Remove(normalized)
	}
	if derr != nil && (!body.Force || !errors.Is(derr, os.ErrNotExist)) {
		writeBrowseError(w, derr, "Failed to delete item")
		return
	}

	kind := "File"
	if info.IsDir() {
		kind = "Directory"
	}
	slog.Info("filesystem item deleted", "path", normalized,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, deleteFileItemResponse{
		Success:     true,
		Message:     kind + " '" + filepath.Base(normalized) + "' deleted successfully",
		DeletedItem: &deletedItem,
	})
}

// changePermissionsRequest is PATCH /filesystem/permissions's body.
type changePermissionsRequest struct {
	Path string `json:"path"`
	UID  *int   `json:"uid"`
	GID  *int   `json:"gid"`
	// Octal permission string, e.g. "644"
	Mode      string `json:"mode"`
	Recursive bool   `json:"recursive"`
}

// permissionChanges echoes the requested changes in a permissions answer.
type permissionChanges struct {
	UID       *int   `json:"uid"`
	GID       *int   `json:"gid"`
	Mode      string `json:"mode"`
	Recursive bool   `json:"recursive"`
}

// changePermissionsResponse is PATCH /filesystem/permissions's answer.
type changePermissionsResponse struct {
	Success        bool              `json:"success"`
	Message        string            `json:"message"`
	Item           fileSystemItem    `json:"item"`
	ChangesApplied permissionChanges `json:"changes_applied"`
}

// handleChangePermissions serves PATCH /filesystem/permissions — the base's
// changePermissions: {path, uid?, gid?, mode?, recursive?}. mode chmods (on
// Windows that is the read-only attribute — Go's honest mapping); uid/gid
// chown on Unix hosts and answer 400 on Windows.
//
//	@Summary		Change permissions or ownership
//	@Description	Minimum role: operator. {path, uid?, gid?, mode?, recursive?} — at least one of uid/gid/mode. mode chmods (on Windows that is Go's honest mapping: the read-only attribute); uid/gid chown on Unix hosts — a Windows host answers 400 (no analog, never a silent no-op). Synchronous.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	changePermissionsRequest	true	"Path plus at least one of uid/gid/mode, optional recursive"
//	@Success		200	{object}	changePermissionsResponse	"Permissions updated ({success, message, item, changes_applied})"
//	@Failure		400	"Missing path, nothing to change, bad mode, or uid/gid on a Windows host"
//	@Failure		403	"Path forbidden"
//	@Failure		404	"Item not found"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/permissions [patch]
func (s *Server) handleChangePermissions(w http.ResponseWriter, r *http.Request) {
	var body changePermissionsRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Path == "" {
		taskError(w, http.StatusBadRequest, "path is required")
		return
	}
	if body.UID == nil && body.GID == nil && body.Mode == "" {
		taskError(w, http.StatusBadRequest, "At least one of uid, gid, or mode must be specified")
		return
	}
	if (body.UID != nil || body.GID != nil) && runtime.GOOS == "windows" {
		taskError(w, http.StatusBadRequest, "uid/gid ownership has no analog on a Windows host (mode toggles the read-only attribute)")
		return
	}
	normalized, err := s.validateBrowsePath(body.Path)
	if err != nil {
		writeBrowseError(w, err, "Failed to update permissions")
		return
	}
	if body.UID != nil || body.GID != nil {
		if cerr := applyOwnership(normalized, body.UID, body.GID, body.Recursive); cerr != nil {
			writeBrowseError(w, cerr, "Failed to change ownership")
			return
		}
	}
	if body.Mode != "" {
		mode, perr := parseOctalMode(body.Mode)
		if perr != nil {
			taskError(w, http.StatusBadRequest, perr.Error())
			return
		}
		if cerr := applyMode(normalized, mode, body.Recursive); cerr != nil {
			writeBrowseError(w, cerr, "Failed to change permissions")
			return
		}
	}
	item, ierr := s.browseItem(normalized)
	if ierr != nil {
		writeBrowseError(w, ierr, "Failed to update permissions")
		return
	}
	writeJSON(w, changePermissionsResponse{
		Success: true,
		Message: "Permissions updated successfully for '" + item.Name + "'",
		Item:    item,
		ChangesApplied: permissionChanges{
			UID:       body.UID,
			GID:       body.GID,
			Mode:      body.Mode,
			Recursive: body.Recursive,
		},
	})
}
