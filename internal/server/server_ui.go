package server

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/version"
)

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
