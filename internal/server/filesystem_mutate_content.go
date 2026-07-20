package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

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
