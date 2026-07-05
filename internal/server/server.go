// Package server hosts the agent's HTTP surface: the public status endpoint
// and the Hyperweaver UI (Direct mode).
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/apidocs"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/version"
	"github.com/Makr91/hyperweaver-agent/internal/webui"
)

// Server is the agent's HTTP server.
type Server struct {
	cfg        *config.Config
	keys       *keys.Store
	trayTokens *auth.TrayTokens
	tasks      *tasks.Queue
	machines   *machines.Store
	httpSrv    *http.Server
	listener   net.Listener
	startedAt  time.Time

	// restartArgs are the arguments a restart-spawned successor process gets —
	// built by main from parsed flag values (never raw os.Args).
	restartArgs []string

	// openUI opens the signed-in UI in the user's browser — the same action a
	// tray Open click performs, injected by main so the hwa:// protocol
	// handoff (POST /protocol/open) shares it exactly.
	openUI func()
}

// New builds the server and its routes.
func New(cfg *config.Config, keyStore *keys.Store, trayTokens *auth.TrayTokens, taskQueue *tasks.Queue, machineStore *machines.Store, restartArgs []string, openUI func()) (*Server, error) {
	s := &Server{
		cfg:         cfg,
		keys:        keyStore,
		trayTokens:  trayTokens,
		tasks:       taskQueue,
		machines:    machineStore,
		startedAt:   time.Now(),
		restartArgs: restartArgs,
		openUI:      openUI,
	}

	mux := http.NewServeMux()

	// Public identity + capabilities probe (Hyperweaver dual-mode contract):
	// /status is the canonical path, /api/status the SPA's discovery alias.
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /api/status", s.handleStatus)

	// API-key surface (Agent API v1 local tier). Bootstrap is public (gated
	// by config + the setup token); everything else goes through the auth
	// middleware, whose central policy enforces the role model per path.
	requireKey := auth.Middleware(s.keys)
	mux.HandleFunc("POST /api-keys/bootstrap", s.handleBootstrapKey)
	mux.HandleFunc("POST /auth/tray-claim", s.handleTrayClaim)
	// hwa:// single-instance handoff: public route, authenticated by the
	// per-boot secret file only a local same-user process can read.
	mux.HandleFunc("POST /protocol/open", s.handleProtocolOpen)
	mux.Handle("POST /api-keys/generate", requireKey(http.HandlerFunc(s.handleGenerateKey)))
	mux.Handle("GET /api-keys", requireKey(http.HandlerFunc(s.handleListKeys)))
	mux.Handle("GET /api-keys/info", requireKey(http.HandlerFunc(s.handleKeyInfo)))
	mux.Handle("DELETE /api-keys/{id}", requireKey(http.HandlerFunc(s.handleDeleteKey)))
	mux.Handle("PUT /api-keys/{id}/revoke", requireKey(http.HandlerFunc(s.handleRevokeKey)))

	// Version / update / prerequisite surfaces (Agent API v1 System group).
	mux.Handle("GET /version", requireKey(http.HandlerFunc(s.handleVersion)))
	mux.Handle("GET /app/updates/check", requireKey(http.HandlerFunc(s.handleUpdateCheck)))
	mux.Handle("GET /provisioning/status", requireKey(http.HandlerFunc(s.handleProvisioningStatus)))

	// Host statistics (shared v1 stats shape). The Node agent optionally
	// serves this publicly (stats.public_access, default false) — this agent
	// keeps it keyed; add the knob only if a consumer ever needs it public.
	mux.Handle("GET /stats", requireKey(http.HandlerFunc(s.handleStats)))

	// Task queue (Agent API v1 Task Management group). Literal patterns
	// (/tasks/stats, /tasks/completed) win over the {taskId} wildcards in
	// ServeMux precedence.
	mux.Handle("GET /tasks", requireKey(http.HandlerFunc(s.handleListTasks)))
	mux.Handle("GET /tasks/stats", requireKey(http.HandlerFunc(s.handleTaskStats)))
	mux.Handle("GET /tasks/{taskId}", requireKey(http.HandlerFunc(s.handleTaskDetails)))
	mux.Handle("GET /tasks/{taskId}/output", requireKey(http.HandlerFunc(s.handleTaskOutput)))
	mux.Handle("DELETE /tasks/completed", requireKey(http.HandlerFunc(s.handleClearCompletedTasks)))
	mux.Handle("DELETE /tasks/{taskId}", requireKey(http.HandlerFunc(s.handleCancelTask)))

	// Machines (Agent API v1, canonical /machines/* noun only — design D-E).
	// Literal segments (ids, bulk) win over {machineName} in ServeMux
	// precedence.
	mux.Handle("GET /machines", requireKey(http.HandlerFunc(s.handleListMachines)))
	mux.Handle("GET /machines/ids", requireKey(http.HandlerFunc(s.handleServerIDs)))
	mux.Handle("GET /machines/ids/next", requireKey(http.HandlerFunc(s.handleNextServerID)))
	mux.Handle("POST /machines/bulk/start", requireKey(http.HandlerFunc(s.handleBulkStart)))
	mux.Handle("POST /machines/bulk/stop", requireKey(http.HandlerFunc(s.handleBulkStop)))
	mux.Handle("GET /machines/{machineName}", requireKey(http.HandlerFunc(s.handleMachineDetails)))
	mux.Handle("GET /machines/{machineName}/config", requireKey(http.HandlerFunc(s.handleMachineConfig)))
	mux.Handle("POST /machines/{machineName}/start", requireKey(http.HandlerFunc(s.handleStartMachine)))
	mux.Handle("POST /machines/{machineName}/stop", requireKey(http.HandlerFunc(s.handleStopMachine)))
	mux.Handle("POST /machines/{machineName}/restart", requireKey(http.HandlerFunc(s.handleRestartMachine)))
	mux.Handle("POST /machines/{machineName}/suspend", requireKey(http.HandlerFunc(s.handleSuspendMachine)))
	mux.Handle("DELETE /machines/{machineName}", requireKey(http.HandlerFunc(s.handleDeleteMachine)))
	mux.Handle("GET /machines/{machineName}/notes", requireKey(http.HandlerFunc(s.handleGetMachineNotes)))
	mux.Handle("PUT /machines/{machineName}/notes", requireKey(http.HandlerFunc(s.handleUpdateMachineNotes)))
	mux.Handle("GET /machines/{machineName}/tags", requireKey(http.HandlerFunc(s.handleGetMachineTags)))
	mux.Handle("PUT /machines/{machineName}/tags", requireKey(http.HandlerFunc(s.handleUpdateMachineTags)))

	// Settings surface (Agent API v1) — admin-only via the central role policy.
	mux.Handle("GET /settings", requireKey(http.HandlerFunc(s.handleGetSettings)))
	mux.Handle("GET /settings/schema", requireKey(http.HandlerFunc(s.handleSettingsSchema)))
	mux.Handle("PUT /settings", requireKey(http.HandlerFunc(s.handleUpdateSettings)))
	mux.Handle("POST /settings/backup", requireKey(http.HandlerFunc(s.handleCreateBackup)))
	mux.Handle("GET /settings/backups", requireKey(http.HandlerFunc(s.handleListBackups)))
	mux.Handle("DELETE /settings/backups/{filename}", requireKey(http.HandlerFunc(s.handleDeleteBackup)))
	mux.Handle("POST /settings/restore/{filename}", requireKey(http.HandlerFunc(s.handleRestoreBackup)))
	mux.Handle("POST /server/restart", requireKey(http.HandlerFunc(s.handleServerRestart)))

	// Interactive Agent API documentation (Swagger UI), Node-agent parity:
	// public /api-docs page + /api-docs/swagger.json, gated by configuration.
	if cfg.APIDocs.Enabled {
		if err := apidocs.Mount(mux); err != nil {
			return nil, err
		}
	}

	uiFS, err := webui.FS(cfg.UI.Path)
	if err != nil {
		return nil, err
	}

	// The docs site rides inside the UI artifact but is served independent of
	// ui.enabled — a docs-only (headless UI) setup still exposes /docs, same
	// as the Node agent.
	mountDocs(mux, uiFS)

	if cfg.UI.Enabled {
		if err := s.mountUI(mux, uiFS); err != nil {
			return nil, err
		}
	} else {
		mux.HandleFunc("GET /{$}", s.handleRootInfo)
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.ListenAddr(),
		Handler:           requestLog(recoverer(mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// mountUI serves the SPA at /ui/ (with client-side-route fallback) and
// redirects / to /ui/.
func (s *Server) mountUI(mux *http.ServeMux, uiFS fs.FS) error {
	source := "embedded"
	if s.cfg.UI.Path != "" {
		source = s.cfg.UI.Path
	}
	slog.Info("serving UI", "source", source)

	index, err := fs.ReadFile(uiFS, "index.html")
	if err != nil {
		return err
	}
	fileServer := http.FileServerFS(uiFS)

	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		if _, statErr := fs.Stat(uiFS, p); statErr != nil {
			// Client-side route: fall back to the SPA entry point. ServeContent
			// (not ServeFileFS) because ServeFileFS redirects */index.html.
			w.Header().Set("Cache-Control", "no-cache")
			http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
			return
		}
		if p == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})))

	mux.Handle("GET /{$}", http.RedirectHandler("/ui/", http.StatusFound))
	return nil
}

// mountDocs serves the docs site the UI artifact carries at dist/docs
// (baseurl /docs). When the docs are not bundled (dev placeholder builds),
// requests get the Node agent's 503-with-guidance answer instead of a bare
// 404. fs.Sub cannot detect a missing directory, so existence is checked
// with fs.Stat.
func mountDocs(mux *http.ServeMux, uiFS fs.FS) {
	if _, err := fs.Stat(uiFS, "docs"); err != nil {
		mux.HandleFunc("GET /docs/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			body := map[string]string{
				"error":   "Documentation not bundled in this build",
				"details": "The docs site ships inside the Hyperweaver UI artifact (dist/docs); use a build with the UI artifact baked in, or point ui.path at one.",
			}
			if err := json.NewEncoder(w).Encode(body); err != nil {
				slog.Error("write docs response", "error", err)
			}
		})
		return
	}

	sub, err := fs.Sub(uiFS, "docs")
	if err != nil {
		mux.Handle("GET /docs/", http.NotFoundHandler())
		return
	}
	mux.Handle("GET /docs/", http.StripPrefix("/docs/", http.FileServerFS(sub)))
}

func (s *Server) handleRootInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	info := map[string]any{
		"name":    "Hyperweaver Agent",
		"version": version.Version,
		"ui":      false,
		"status":  "/api/status",
	}
	if err := json.NewEncoder(w).Encode(info); err != nil {
		slog.Error("write root response", "error", err)
	}
}

// Listen binds the configured address without serving yet. Split from Start
// so main can detect a bind conflict — the single-instance signal — before
// any tray icon is shown, and hand the action to the instance that owns the
// port instead.
func (s *Server) Listen() error {
	listener, err := s.listen()
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

// Start blocks serving HTTP until Shutdown is called or the listener fails.
func (s *Server) Start() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	slog.Info("http server listening", "addr", s.httpSrv.Addr, "ui_enabled", s.cfg.UI.Enabled)
	err := s.httpSrv.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// listen binds the configured address. A process spawned by /server/restart
// (HYPERWEAVER_RESTART=1) retries for a few seconds while its predecessor
// releases the port.
func (s *Server) listen() (net.Listener, error) {
	attempts := 1
	if os.Getenv("HYPERWEAVER_RESTART") == "1" {
		attempts = 20
	}

	// Server-lifetime bind, not request-scoped — Background is correct here.
	listenConfig := net.ListenConfig{}
	var lastErr error
	for i := 0; i < attempts; i++ {
		listener, err := listenConfig.Listen(context.Background(), "tcp", s.cfg.ListenAddr())
		if err == nil {
			return listener, nil
		}
		lastErr = err
		if attempts > 1 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return nil, lastErr
}

// Shutdown gracefully drains connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// requestLog logs each request at debug level.
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// recoverer converts handler panics into 500s instead of killing the process.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("handler panic", "panic", rec, "path", r.URL.Path)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
