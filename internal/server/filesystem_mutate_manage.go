package server

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
)

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
