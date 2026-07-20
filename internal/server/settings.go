package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Settings endpoints (Agent API v1): expose the agent's own config.yaml over
// the same surface the Node agent provides — GET/PUT /settings, the schema
// (the settingsSchema literal lives in settings_schema.go), timestamped
// backups with restore, and /server/restart. The AgentSettings page renders
// its tabs directly from the GET /settings sections.

// @Summary		Current agent configuration
// @Description	Minimum role: admin. Returns the live configuration with the same section and key names as config.yaml.
// @Tags			Settings
// @Produce		json
// @Success		200	{object}	config.Config	"The configuration document"
// @Router			/settings [get]
func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	// The live configuration, JSON-tagged with the same names as the YAML.
	// Nothing secret lives in it today; sanitize here when that changes.
	writeJSON(w, s.cfg)
}

// @Summary		Settings schema
// @Description	Minimum role: admin. Section/field types, descriptions, defaults, ranges, and restart requirements — the document the settings UI renders its tabs from.
// @Tags			Settings
// @Produce		json
// @Success		200	{object}	map[string]interface{}	"The schema document"
// @Router			/settings/schema [get]
func (s *Server) handleSettingsSchema(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, settingsSchema)
}

type updateSettingsResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// @Summary		Update agent configuration
// @Description	Minimum role: admin. Shallow-merges the submitted top-level sections onto the on-disk YAML, validates the result, backs up the current file, and writes atomically. The running process keeps its loaded values — most changes apply on restart.
// @Tags			Settings
// @Accept			json
// @Produce		json
// @Param			request	body		map[string]interface{}	true	"Top-level configuration sections to replace"
// @Success		200		{object}	updateSettingsResponse	"Settings persisted"
// @Failure		400		{object}	wrappedError			"Invalid JSON body"
// @Failure		500		{object}	wrappedError			"Merged configuration invalid or write failure"
// @Router			/settings [put]
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var updates map[string]any
	if err := decodeBody(r, &updates); err != nil || updates == nil {
		errorResponse(w, http.StatusBadRequest, "Failed to update settings", "Invalid JSON body")
		return
	}

	if err := s.cfg.MergeAndSave(updates); err != nil {
		slog.Error("settings update failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to update settings", err.Error())
		return
	}
	slog.Info("settings updated", "by", auth.FromContext(r.Context()).Name)

	writeJSON(w, updateSettingsResponse{
		Success: true,
		Message: "Settings updated successfully. Some changes may require a server restart.",
	})
}

type createBackupResponse struct {
	Success bool           `json:"success"`
	Message string         `json:"message"`
	Backup  *config.Backup `json:"backup"`
}

// @Summary		Create a configuration backup
// @Description	Minimum role: admin.
// @Tags			Settings
// @Produce		json
// @Success		200	{object}	createBackupResponse	"Backup created"
// @Router			/settings/backup [post]
func (s *Server) handleCreateBackup(w http.ResponseWriter, _ *http.Request) {
	backup, err := s.cfg.CreateBackup()
	if err != nil {
		slog.Error("backup creation failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to create backup", err.Error())
		return
	}
	writeJSON(w, createBackupResponse{
		Success: true,
		Message: "Backup created successfully",
		Backup:  backup,
	})
}

// @Summary		List configuration backups
// @Description	Minimum role: admin. Newest first.
// @Tags			Settings
// @Produce		json
// @Success		200	{array}	config.Backup	"All backups"
// @Router			/settings/backups [get]
func (s *Server) handleListBackups(w http.ResponseWriter, _ *http.Request) {
	backups, err := s.cfg.ListBackups()
	if err != nil {
		slog.Error("backup listing failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to list backups", err.Error())
		return
	}
	writeJSON(w, backups)
}

type deleteBackupResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// @Summary		Delete a configuration backup
// @Description	Minimum role: admin. Only agent-generated backup names (config-<unix-ms>.yaml) are accepted.
// @Tags			Settings
// @Produce		json
// @Param			filename	path		string					true	"Backup filename"
// @Success		200			{object}	deleteBackupResponse	"Backup deleted"
// @Failure		404			{object}	wrappedError			"Backup not found"
// @Router			/settings/backups/{filename} [delete]
func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if err := s.cfg.DeleteBackup(filename); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			errorResponse(w, http.StatusNotFound, "Backup not found", "")
			return
		}
		slog.Error("backup deletion failed", "error", err, "filename", filename)
		errorResponse(w, http.StatusBadRequest, "Failed to delete backup", err.Error())
		return
	}
	writeJSON(w, deleteBackupResponse{
		Success: true,
		Message: "Backup " + filename + " deleted successfully.",
	})
}

type restoreBackupResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// @Summary		Restore configuration from a backup
// @Description	Minimum role: admin. The backup is validated as a working configuration and the current file is backed up first.
// @Tags			Settings
// @Produce		json
// @Param			filename	path		string					true	"Backup filename"
// @Success		200			{object}	restoreBackupResponse	"Configuration restored"
// @Failure		404			{object}	wrappedError			"Backup not found"
// @Router			/settings/restore/{filename} [post]
func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if err := s.cfg.RestoreBackup(filename); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			errorResponse(w, http.StatusNotFound, "Backup not found", "")
			return
		}
		slog.Error("backup restore failed", "error", err, "filename", filename)
		errorResponse(w, http.StatusInternalServerError, "Failed to restore backup", err.Error())
		return
	}
	slog.Info("configuration restored from backup", "filename", filename,
		"by", auth.FromContext(r.Context()).Name)

	writeJSON(w, restoreBackupResponse{
		Success: true,
		Message: "Restored configuration from " + filename + ". A server restart may be required.",
	})
}

type serverRestartResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// @Summary		Restart the agent
// @Description	Minimum role: admin. Under systemd the unit's Restart=always brings the agent back after a clean exit; everywhere else the agent spawns its own successor before shutting down.
// @Tags			Settings
// @Produce		json
// @Success		200	{object}	serverRestartResponse	"Restart initiated"
// @Router			/server/restart [post]
func (s *Server) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	slog.Warn("server restart requested", "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, serverRestartResponse{
		Success: true,
		Message: "Server restart initiated. Please wait a few seconds before reconnecting. The server will reload all configuration changes.",
	})
	// WithoutCancel: the restart must survive this request completing, while
	// staying derived from the request that authorized it.
	go s.restartSelf(context.WithoutCancel(r.Context()))
}

// Restart restarts the agent process — /server/restart's exact mechanism
// without the HTTP wrapper (the tray's Troubleshooting action).
func (s *Server) Restart() {
	slog.Warn("server restart requested from the tray")
	go s.restartSelf(context.Background())
}

// restartSelf restarts the agent process. Under systemd the unit's
// Restart=always brings it back after a clean exit; everywhere else a
// detached copy of this executable is spawned (with a bind-retry handshake so
// the child can wait for this process to release the port). The successor's
// arguments come from main's parsed flags, never raw process arguments.
func (s *Server) restartSelf(parent context.Context) {
	// Let the HTTP response flush before tearing anything down.
	time.Sleep(time.Second)

	if os.Getenv("INVOCATION_ID") == "" { // not systemd: spawn our successor first
		exe, err := os.Executable()
		if err != nil {
			slog.Error("restart: resolve executable", "error", err)
			return
		}
		validated, err := safepath.ValidateExecutable(exe)
		if err != nil {
			slog.Error("restart: validate executable", "error", err)
			return
		}
		cmd := exec.CommandContext(parent, validated, s.restartArgs...)
		cmd.Env = append(os.Environ(), "HYPERWEAVER_RESTART=1")
		cmd.SysProcAttr = procattr.NoConsole()
		if err := cmd.Start(); err != nil {
			slog.Error("restart: spawn successor", "error", err)
			return
		}
	}

	shutdownCtx, cancel := context.WithTimeout(parent, 5*time.Second)
	err := s.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		slog.Error("restart: shutdown", "error", err)
	}
	slog.Info("hyperweaver-agent restarting")
	os.Exit(0)
}
