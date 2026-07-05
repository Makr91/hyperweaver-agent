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
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/version"
	"github.com/Makr91/hyperweaver-agent/internal/webui"
)

// Server is the agent's HTTP server.
type Server struct {
	cfg       *config.Config
	httpSrv   *http.Server
	startedAt time.Time
}

// New builds the server and its routes.
func New(cfg *config.Config) (*Server, error) {
	s := &Server{
		cfg:       cfg,
		startedAt: time.Now(),
	}

	mux := http.NewServeMux()

	// Public identity + capabilities probe (Hyperweaver dual-mode contract):
	// /status is the canonical path, /api/status the SPA's discovery alias.
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /api/status", s.handleStatus)

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

// Start blocks serving HTTP until Shutdown is called or the listener fails.
func (s *Server) Start() error {
	slog.Info("http server listening", "addr", s.httpSrv.Addr, "ui_enabled", s.cfg.UI.Enabled)
	err := s.httpSrv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
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
