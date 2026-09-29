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
	"github.com/Makr91/hyperweaver-agent/internal/configengine"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

const configUploadLimit = 1024 * 1024

func (s *Server) mountConfigRoutes(mux *http.ServeMux, requireKey func(http.Handler) http.Handler) {
	s.cfg.Engine().Routes(mux, configengine.Auth{
		Admin: requireKey,
		Actor: func(r *http.Request) string {
			if identity := auth.FromContext(r.Context()); identity != nil {
				return identity.Name
			}
			return ""
		},
	}, s.restartSelf, configUploadLimit)
	mux.Handle("GET /api/config/backups", requireKey(http.HandlerFunc(s.handleListBackups)))
	mux.Handle("POST /api/config/backups", requireKey(http.HandlerFunc(s.handleCreateBackup)))
	mux.Handle("DELETE /api/config/backups/{id}", requireKey(http.HandlerFunc(s.handleDeleteBackup)))
	mux.Handle("POST /api/config/backups/{id}/restore", requireKey(http.HandlerFunc(s.handleRestoreBackup)))
}

type createBackupResponse struct {
	Message string         `json:"message"`
	Backup  *config.Backup `json:"backup"`
}

// @Summary		Back up every configuration file
// @Description	Minimum role: admin. Copies the five configuration files into a new timestamped folder under backups beside them; the one .bak the engine writes on every save is separate from this history.
// @Tags			Configuration
// @Produce		json
// @Success		200	{object}	createBackupResponse	"Backup created"
// @Failure		500	{object}	problem.Body			"The files could not be copied"
// @Router			/api/config/backups [post]
func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	backup, err := s.cfg.CreateBackup()
	if err != nil {
		slog.Error("backup creation failed", "error", err)
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	slog.Info("configuration backup created", "id", backup.ID, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, createBackupResponse{Message: "Backup created.", Backup: backup})
}

// @Summary		List configuration backups
// @Description	Minimum role: admin. Newest first; each carries the files it holds.
// @Tags			Configuration
// @Produce		json
// @Success		200	{array}	config.Backup	"All backups"
// @Router			/api/config/backups [get]
func (s *Server) handleListBackups(w http.ResponseWriter, _ *http.Request) {
	backups, err := s.cfg.ListBackups()
	if err != nil {
		slog.Error("backup listing failed", "error", err)
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	writeJSON(w, backups)
}

// @Summary		Delete a configuration backup
// @Description	Minimum role: admin.
// @Tags			Configuration
// @Produce		json
// @Param			id	path		string							true	"Backup id, the timestamp folder name"
// @Success		200	{object}	configengine.MessageResponse	"Backup deleted"
// @Failure		404	{object}	problem.Body					"Backup not found"
// @Router			/api/config/backups/{id} [delete]
func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.DeleteBackup(id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			problem.NotFound(w)
			return
		}
		slog.Error("backup deletion failed", "error", err, "id", id)
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	writeJSON(w, configengine.MessageResponse{Message: "Backup " + id + " deleted."})
}

// @Summary		Restore the configuration files from a backup
// @Description	Minimum role: admin. Every file of the backup is validated against its schema, the current files are backed up first, then each is written through the engine; the restart list records the changed values.
// @Tags			Configuration
// @Produce		json
// @Param			id	path		string							true	"Backup id"
// @Success		200	{object}	configengine.MessageResponse	"Configuration restored"
// @Failure		404	{object}	problem.Body					"Backup not found"
// @Failure		422	{object}	problem.Body					"A backed-up value breaks its schema"
// @Router			/api/config/backups/{id}/restore [post]
func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.cfg.RestoreBackup(id)
	var verr *configengine.ValidationError
	switch {
	case errors.Is(err, os.ErrNotExist):
		problem.NotFound(w)
		return
	case errors.As(err, &verr):
		problem.Refuse(w, verr.Errors, "The configuration did not pass validation.")
		return
	case err != nil:
		slog.Error("backup restore failed", "error", err, "id", id)
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	slog.Info("configuration restored from backup", "id", id, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, configengine.MessageResponse{Message: "Restored configuration from backup " + id + "."})
}

// Restart restarts the agent process, the tray's Troubleshooting action.
func (s *Server) Restart() {
	slog.Warn("server restart requested from the tray")
	go s.restartSelf()
}

func (s *Server) expectSuccessor() {
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	s.successorExpected = true
}

func (s *Server) successorPending() bool {
	s.handoffMu.Lock()
	defer s.handoffMu.Unlock()
	return s.successorExpected
}

// restartSelf restarts the agent process. Under systemd the unit's
// Restart=always brings it back after a clean exit; everywhere else a
// detached copy of this executable is spawned, which asks over the handoff
// channel and is answered only once the services and databases are closed
// and the listeners after them, so a successor refused instead finds nothing
// held. The successor's arguments come from main's parsed flags, never raw
// process arguments.
func (s *Server) restartSelf() {
	if os.Getenv("INVOCATION_ID") == "" {
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
		s.expectSuccessor()
		cmd := exec.CommandContext(context.Background(), validated, s.restartArgs...)
		cmd.SysProcAttr = procattr.NoConsole()
		if err := cmd.Start(); err != nil {
			slog.Error("restart: spawn successor", "error", err)
			return
		}
	}

	s.teardown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(shutdownCtx) }()
	close(s.released)
	if err := <-done; err != nil {
		slog.Error("restart: shutdown", "error", err)
	}
	slog.Info("hyperweaver-agent restarting")
	os.Exit(0)
}
