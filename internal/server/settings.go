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
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Settings endpoints (Agent API v1): expose the agent's own config.yaml over
// the same surface the Node agent provides — GET/PUT /settings, the schema,
// timestamped backups with restore, and /server/restart. The AgentSettings
// page renders its tabs directly from the GET /settings sections.

// settingsSchema describes this agent's configuration sections: types,
// descriptions, defaults, ranges, and restart requirements (the Node agent's
// /settings/schema shape).
var settingsSchema = map[string]any{
	"server": map[string]any{
		"description":      "HTTP server configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"bind_address": map[string]any{
				"type":        "string",
				"description": "Address the web server binds to (keep 127.0.0.1 for local-only access)",
				"default":     "127.0.0.1",
			},
			"port": map[string]any{
				"type":        "integer",
				"description": "Web server port",
				"default":     9420,
				"min":         1,
				"max":         65535,
			},
		},
	},
	"ui": map[string]any{
		"description":      "Hyperweaver UI serving configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the Hyperweaver UI at /ui/",
				"default":     true,
			},
			"path": map[string]any{
				"type":        "string",
				"description": "Serve the UI from this directory instead of the embedded copy (empty = embedded)",
				"default":     "",
			},
		},
	},
	"browser": map[string]any{
		"description":      "Tray Open browser configuration",
		"requires_restart": false,
		"properties": map[string]any{
			"path": map[string]any{
				"type":        "string",
				"description": "Browser executable (or macOS .app) the tray Open action launches (empty = system default)",
				"default":     "",
			},
		},
	},
	"logging": map[string]any{
		"description":      "Application logging configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"level": map[string]any{
				"type":        "string",
				"description": "Log level",
				"default":     "info",
				"enum":        []string{"error", "warn", "info", "debug"},
			},
			"console": map[string]any{
				"type":        "boolean",
				"description": "Also log human-readable output to the console",
				"default":     true,
			},
			"file": map[string]any{
				"type":        "string",
				"description": "Log file location (empty = <config dir>/logs/agent.log)",
				"default":     "",
			},
			"max_size_mb": map[string]any{
				"type":        "integer",
				"description": "Maximum log file size in MB before rotation",
				"default":     20,
				"min":         1,
			},
			"max_backups": map[string]any{
				"type":        "integer",
				"description": "Number of rotated log files to keep",
				"default":     5,
				"min":         0,
			},
		},
	},
	"api_keys": map[string]any{
		"description":      "API key authentication configuration",
		"requires_restart": false,
		"properties": map[string]any{
			"bootstrap_enabled": map[string]any{
				"type":        "boolean",
				"description": "Enable bootstrap key generation endpoint",
				"default":     true,
			},
			"bootstrap_auto_disable": map[string]any{
				"type":        "boolean",
				"description": "Auto-disable bootstrap after the first key exists",
				"default":     true,
			},
			"bootstrap_require_claim_token": map[string]any{
				"type":        "boolean",
				"description": "Require the setup (claim) token as proof of host ownership",
				"default":     true,
			},
			"key_length": map[string]any{
				"type":        "integer",
				"description": "Random byte length for API key generation",
				"default":     64,
				"min":         16,
				"max":         256,
			},
			"hash_rounds": map[string]any{
				"type":        "integer",
				"description": "bcrypt hash rounds for API key storage",
				"default":     12,
				"min":         4,
				"max":         20,
			},
		},
	},
	"updates": map[string]any{
		"description":      "Application update checking configuration",
		"requires_restart": false,
		"properties": map[string]any{
			"versioninfo_url": map[string]any{
				"type":        "string",
				"description": "URL to the remote versioninfo document for update checking (empty disables)",
				"default":     "https://github.com/Makr91/hyperweaver-agent/releases/latest/download/update-info.json",
			},
		},
	},
	"api_docs": map[string]any{
		"description":      "Interactive API documentation (Swagger UI)",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the Agent API documentation at /api-docs",
				"default":     true,
			},
		},
	},
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	// The live configuration, JSON-tagged with the same names as the YAML.
	// Nothing secret lives in it today; sanitize here when that changes.
	writeJSON(w, s.cfg)
}

func (s *Server) handleSettingsSchema(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, settingsSchema)
}

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

	writeJSON(w, map[string]any{
		"success": true,
		"message": "Settings updated successfully. Some changes may require a server restart.",
	})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, _ *http.Request) {
	backup, err := s.cfg.CreateBackup()
	if err != nil {
		slog.Error("backup creation failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to create backup", err.Error())
		return
	}
	writeJSON(w, map[string]any{
		"success": true,
		"message": "Backup created successfully",
		"backup":  backup,
	})
}

func (s *Server) handleListBackups(w http.ResponseWriter, _ *http.Request) {
	backups, err := s.cfg.ListBackups()
	if err != nil {
		slog.Error("backup listing failed", "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to list backups", err.Error())
		return
	}
	writeJSON(w, backups)
}

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
	writeJSON(w, map[string]any{
		"success": true,
		"message": "Backup " + filename + " deleted successfully.",
	})
}

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

	writeJSON(w, map[string]any{
		"success": true,
		"message": "Restored configuration from " + filename + ". A server restart may be required.",
	})
}

func (s *Server) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	slog.Warn("server restart requested", "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"message": "Server restart initiated. Please wait a few seconds before reconnecting. The server will reload all configuration changes.",
	})
	// WithoutCancel: the restart must survive this request completing, while
	// staying derived from the request that authorized it.
	go s.restartSelf(context.WithoutCancel(r.Context()))
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
