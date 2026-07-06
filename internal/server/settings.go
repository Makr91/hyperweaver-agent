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
		"description":      "HTTP/HTTPS server configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"bind_address": map[string]any{
				"type":        "string",
				"description": "Address the web server binds to (keep 127.0.0.1 for local-only access)",
				"default":     "127.0.0.1",
			},
			"port": map[string]any{
				"type":        "integer",
				"description": "HTTP server port",
				"default":     9420,
				"min":         1,
				"max":         65535,
			},
			"https_port": map[string]any{
				"type":        "integer",
				"description": "HTTPS server port (bound only when ssl.enabled)",
				"default":     9421,
				"min":         1,
				"max":         65535,
			},
		},
	},
	"ssl": map[string]any{
		"description":      "SSL/TLS certificate configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Enable HTTPS on server.https_port (certificate problems leave the agent HTTP-only, never down)",
				"default":     true,
			},
			"force_secure": map[string]any{
				"type":        "boolean",
				"description": "With SSL enabled, the plain-HTTP port serves only redirects to HTTPS; false keeps it serving the full app alongside HTTPS (for clients that cannot follow redirects)",
				"default":     true,
			},
			"generate_ssl": map[string]any{
				"type":        "boolean",
				"description": "Auto-generate the server certificate when none exists, signed by the CA (generated too when absent)",
				"default":     true,
			},
			"key_path": map[string]any{
				"type":        "string",
				"description": "Path to the server SSL private key file (empty = <config dir>/ssl/server.key)",
				"default":     "",
			},
			"cert_path": map[string]any{
				"type":        "string",
				"description": "Path to the server SSL certificate file (empty = <config dir>/ssl/server.crt)",
				"default":     "",
			},
			"ca_cert_path": map[string]any{
				"type":        "string",
				"description": "CA certificate that signs the generated server certificate — provide your own CA here (empty = <config dir>/ssl/ca.crt)",
				"default":     "",
			},
			"ca_key_path": map[string]any{
				"type":        "string",
				"description": "CA private key (empty = <config dir>/ssl/ca.key)",
				"default":     "",
			},
		},
	},
	"cors": map[string]any{
		"description":      "Cross-Origin Resource Sharing configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"allow_all": map[string]any{
				"type":        "boolean",
				"description": "Answer any browser Origin (the API key is the access boundary); false falls back to the whitelist",
				"default":     true,
			},
			"whitelist": map[string]any{
				"type":        "array",
				"items":       "string",
				"description": "Allowed origins for CORS requests when allow_all is false",
				"default":     []string{},
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
			"compression": map[string]any{
				"type":        "boolean",
				"description": "Gzip rotated log files",
				"default":     true,
			},
			"categories": map[string]any{
				"type":        "object",
				"description": "Per-category log levels overriding the global level (map of category name to level)",
				// A free-form map, not fixed fields: keys are category names,
				// values are levels. The vocabularies the editor needs:
				"keys":   []string{"app", "api_requests", "auth", "tasks", "machines", "monitoring"},
				"values": []string{"error", "warn", "info", "debug"},
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
	"stats": map[string]any{
		"description":      "Server statistics endpoint configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"public_access": map[string]any{
				"type":        "boolean",
				"description": "Allow unauthenticated access to the /stats endpoint",
				"default":     false,
			},
		},
	},
	"data": map[string]any{
		"description":      "Data storage locations",
		"requires_restart": true,
		"properties": map[string]any{
			"dir": map[string]any{
				"type":        "string",
				"description": "Root directory for agent data — databases now; machine directories, provisioners, and the file cache later (empty = per-OS local app-data default)",
				"default":     "",
			},
		},
	},
	"database": map[string]any{
		"description":      "SQLite tuning applied to both agent databases",
		"requires_restart": true,
		"properties": map[string]any{
			"sqlite_options": map[string]any{
				"type":        "object",
				"description": "SQLite session pragmas",
				"properties": map[string]any{
					"journal_mode": map[string]any{
						"type":        "string",
						"description": "Journal mode",
						"default":     "WAL",
						"enum":        []string{"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"},
					},
					"synchronous": map[string]any{
						"type":        "string",
						"description": "Durability/speed trade-off",
						"default":     "NORMAL",
						"enum":        []string{"OFF", "NORMAL", "FULL", "EXTRA"},
					},
					"cache_size_mb": map[string]any{
						"type":        "integer",
						"description": "Page cache size in megabytes",
						"default":     128,
						"min":         1,
						"max":         8192,
					},
					"temp_store": map[string]any{
						"type":        "string",
						"description": "Where temporary tables and indexes live",
						"default":     "MEMORY",
						"enum":        []string{"DEFAULT", "FILE", "MEMORY"},
					},
					"mmap_size_mb": map[string]any{
						"type":        "integer",
						"description": "Memory-mapped I/O window in megabytes (0 disables)",
						"default":     512,
						"min":         0,
						"max":         16384,
					},
					"busy_timeout_ms": map[string]any{
						"type":        "integer",
						"description": "Milliseconds to wait on a locked database",
						"default":     30000,
						"min":         100,
						"max":         600000,
					},
					"wal_autocheckpoint": map[string]any{
						"type":        "integer",
						"description": "WAL checkpoint threshold in pages (0 disables automatic checkpoints)",
						"default":     1000,
						"min":         0,
						"max":         1000000,
					},
					"optimize": map[string]any{
						"type":        "boolean",
						"description": "Run PRAGMA optimize when opening each database",
						"default":     true,
					},
				},
			},
		},
	},
	"tasks": map[string]any{
		"description":      "Task queue configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"poll_interval_seconds": map[string]any{
				"type":        "integer",
				"description": "Seconds between task-queue polls",
				"default":     2,
				"min":         1,
				"max":         60,
			},
			"max_concurrent": map[string]any{
				"type":        "integer",
				"description": "Maximum number of tasks running at once",
				"default":     5,
				"min":         1,
				"max":         64,
			},
			"default_pagination_limit": map[string]any{
				"type":        "integer",
				"description": "Default limit for GET /tasks when the request does not send one",
				"default":     50,
				"min":         1,
				"max":         1000,
			},
			"retention_days": map[string]any{
				"type":        "integer",
				"description": "Completed/failed/cancelled tasks older than this many days are deleted by the periodic cleanup",
				"default":     30,
				"min":         1,
				"max":         3650,
			},
			"output": map[string]any{
				"type":        "object",
				"description": "Task output capture (live streaming + persistence)",
				"properties": map[string]any{
					"enabled": map[string]any{
						"type":        "boolean",
						"description": "Capture task output",
						"default":     true,
					},
					"mode": map[string]any{
						"type":        "string",
						"description": "full keeps every output line; circular caps the in-memory buffer, dropping the oldest",
						"default":     "full",
						"enum":        []string{"full", "circular"},
					},
					"circular_max_lines": map[string]any{
						"type":        "integer",
						"description": "Buffer cap for circular mode",
						"default":     10000,
						"min":         100,
					},
					"flush_interval_seconds": map[string]any{
						"type":        "integer",
						"description": "Seconds between database flushes of a running task's output",
						"default":     10,
						"min":         1,
						"max":         300,
					},
					"persist_log_file": map[string]any{
						"type":        "boolean",
						"description": "Also write a plain-text per-task log file when a task finishes",
						"default":     true,
					},
					"log_directory": map[string]any{
						"type":        "string",
						"description": "Directory for per-task log files (empty = <config dir>/logs/tasks)",
						"default":     "",
					},
				},
			},
		},
	},
	"machines": map[string]any{
		"description":      "Machine registry configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"auto_discovery": map[string]any{
				"type":        "boolean",
				"description": "Create a periodic background discover task that reconciles the registry against VirtualBox and vagrant (the startup discovery always runs)",
				"default":     true,
			},
			"discovery_interval": map[string]any{
				"type":        "integer",
				"description": "Seconds between periodic discover tasks",
				"default":     300,
				"min":         10,
				"max":         86400,
			},
			"server_id_start": map[string]any{
				"type":        "integer",
				"description": "Lowest auto-assigned server_id",
				"default":     1,
				"min":         1,
				"max":         99999999,
			},
			"shutdown_timeout": map[string]any{
				"type":        "integer",
				"description": "Seconds a graceful stop waits for the guest to power off after the ACPI signal before forcing poweroff",
				"default":     120,
				"min":         5,
				"max":         3600,
			},
		},
	},
	"cleanup": map[string]any{
		"description":      "Periodic cleanup service configuration",
		"requires_restart": true,
		"properties": map[string]any{
			"interval": map[string]any{
				"type":        "integer",
				"description": "Cleanup cycle interval in seconds (task retention runs on it)",
				"default":     300,
				"min":         60,
				"max":         86400,
			},
		},
	},
	"monitoring": map[string]any{
		"description":      "Host telemetry configuration (/monitoring endpoints always serve realtime samples; storage adds history)",
		"requires_restart": true,
		"properties": map[string]any{
			"storage_enabled": map[string]any{
				"type":        "boolean",
				"description": "Store telemetry time series in per-datatype database files (monitoring-cpu/-memory/-network.sqlite) for history charts; off = realtime samples only",
				"default":     false,
			},
			"collection_interval": map[string]any{
				"type":        "integer",
				"description": "Seconds between collector samples (when storage is enabled)",
				"default":     60,
				"min":         5,
				"max":         3600,
			},
			"retention_days": map[string]any{
				"type":        "integer",
				"description": "Stored samples older than this many days are deleted by the periodic cleanup",
				"default":     7,
				"min":         1,
				"max":         365,
			},
		},
	},
	"host_power": map[string]any{
		"description":      "Host power management (/system/host endpoints and the host-power capability token)",
		"requires_restart": true,
		"properties": map[string]any{
			"enabled": map[string]any{
				"type":        "boolean",
				"description": "Serve the host power endpoints: status/uptime plus admin-only shutdown, restart, poweroff, and halt of the machine this agent runs on",
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
