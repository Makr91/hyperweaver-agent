package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/version"
)

const uiIndex = "index.html"

type uiFileTag struct {
	size     int64
	modified time.Time
	etag     string
}

type uiFiles struct {
	fsys fs.FS
	mu   sync.Mutex
	tags map[string]uiFileTag
}

func (u *uiFiles) etag(name string, info fs.FileInfo, file io.ReadSeeker) (string, error) {
	u.mu.Lock()
	known, ok := u.tags[name]
	u.mu.Unlock()
	if ok && known.size == info.Size() && known.modified.Equal(info.ModTime()) {
		return known.etag, nil
	}

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	etag := `"` + hex.EncodeToString(digest.Sum(nil)) + `"`

	u.mu.Lock()
	u.tags[name] = uiFileTag{size: info.Size(), modified: info.ModTime(), etag: etag}
	u.mu.Unlock()
	return etag, nil
}

func (u *uiFiles) open(name string) (fs.File, fs.FileInfo, error) {
	file, err := u.fsys.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, nil, fs.ErrNotExist
	}
	return file, info, nil
}

func (u *uiFiles) serve(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		name = uiIndex
	}
	file, info, err := u.open(name)
	if (errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid)) && name != uiIndex {
		name = uiIndex
		file, info, err = u.open(name)
	}
	if err != nil {
		slog.Error("open UI file", "file", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = file.Close()
	}()

	content, ok := file.(io.ReadSeeker)
	if !ok {
		slog.Error("UI file is not seekable", "file", name)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if name == uiIndex {
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, name, time.Time{}, content)
		return
	}

	etag, err := u.etag(name, info, content)
	if err != nil {
		slog.Error("hash UI file", "file", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	http.ServeContent(w, r, name, time.Time{}, content)
}

func (s *Server) mountUI(mux *http.ServeMux, uiFS fs.FS) error {
	source := "embedded"
	if s.cfg.UI.Path != "" {
		source = s.cfg.UI.Path
	}
	slog.Info("serving UI", "source", source)

	if _, err := fs.Stat(uiFS, uiIndex); err != nil {
		return err
	}
	files := &uiFiles{fsys: uiFS, tags: map[string]uiFileTag{}}
	mux.HandleFunc("GET /", files.serve)
	return nil
}

func handleUnknownAPI(w http.ResponseWriter, _ *http.Request) {
	taskError(w, http.StatusNotFound, "Not found")
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
