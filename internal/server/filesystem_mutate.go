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
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
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
