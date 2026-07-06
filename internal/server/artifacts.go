package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Installer file cache endpoints (the `artifacts` capability token,
// config-gated by assets.enabled — Mark's ruling 2026-07-06: hash
// verification implemented in full). Files enter the cache by upload,
// local-path registration, or URL download (task-queued with progress);
// every entry point hashes; materialization refuses what fails verification.

// assetsGate answers 503 while the assets subsystem is disabled (the
// config-gated-503 convention its capability token mirrors).
func (s *Server) assetsGate(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Assets.Enabled {
			taskError(w, http.StatusServiceUnavailable, "Assets subsystem is disabled")
			return
		}
		next(w, r)
	})
}

// handleListArtifacts: the cache registry, filterable.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := assets.ListFilter{
		Role: query.Get("role"),
		Kind: query.Get("kind"),
	}
	if raw := query.Get("exists"); raw != "" {
		exists := raw == "true"
		filter.Exists = &exists
	}
	list, err := s.assets.List(r.Context(), &filter)
	if err != nil {
		slog.Error("list artifacts", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve artifacts")
		return
	}
	writeJSON(w, map[string]any{
		"artifacts": list,
		"total":     len(list),
	})
}

// handleScanArtifacts queues an artifact_scan task.
func (s *Server) handleScanArtifacts(w http.ResponseWriter, r *http.Request) {
	var meta assets.ScanMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue scan task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   assets.OpScan,
		Priority:    tasks.PriorityBackground,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue artifact scan", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue scan task")
		return
	}
	acceptedTask(w, task.ID, "Artifact scan task queued successfully")
}

// handleDownloadArtifact queues an artifact_download task.
func (s *Server) handleDownloadArtifact(w http.ResponseWriter, r *http.Request) {
	var meta assets.DownloadMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue download task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   assets.OpDownload,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue artifact download", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue download task")
		return
	}
	acceptedTask(w, task.ID, "Artifact download task queued successfully")
}

// acceptedTask writes the 202 task-created shape.
func acceptedTask(w http.ResponseWriter, taskID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"task_id": taskID,
		"status":  tasks.StatusPending,
		"message": message,
	}); err != nil {
		slog.Error("write accepted response", "error", err)
	}
}

// handleUploadArtifact streams a multipart upload into the cache: fields
// role + kind (+ optional filename overriding the part's name), file part
// "file". The whole body is capped by assets.max_upload_gb.
func (s *Server) handleUploadArtifact(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.Assets.MaxUploadGB)<<30)

	reader, err := r.MultipartReader()
	if err != nil {
		taskError(w, http.StatusBadRequest, "Request must be multipart/form-data")
		return
	}

	role, kind, filename := "", "", ""
	var artifact *assets.Artifact
	for {
		part, perr := reader.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			taskError(w, http.StatusBadRequest, "Malformed multipart body: "+perr.Error())
			return
		}
		switch part.FormName() {
		case "role":
			role = formValue(part)
		case "kind":
			kind = formValue(part)
		case "filename":
			filename = formValue(part)
		case "file":
			// Fields must precede the file part — the stream is single-pass.
			name := filename
			if name == "" {
				name = part.FileName()
			}
			if !assets.ValidRole(role) || !assets.ValidKind(kind) || !assets.ValidFilename(name) {
				taskError(w, http.StatusBadRequest,
					"role, kind, and a usable filename must precede the file part")
				return
			}
			ingested, ierr := s.assets.IngestReader(r.Context(), role, kind, name, part)
			if ierr != nil {
				slog.Error("artifact upload failed", "error", ierr)
				taskError(w, http.StatusInternalServerError, "Upload failed: "+ierr.Error())
				return
			}
			artifact = ingested
		default:
			// Unknown parts are drained and ignored.
			_, _ = io.Copy(io.Discard, part)
		}
		_ = part.Close()
	}
	if artifact == nil {
		taskError(w, http.StatusBadRequest, `multipart body carries no "file" part`)
		return
	}

	slog.Info("artifact uploaded", "role", artifact.Role, "kind", artifact.Kind,
		"filename", artifact.Filename, "sha256", artifact.SHA256,
		"by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"artifact": artifact,
		"verified": artifact.Verified(),
		"message":  "File uploaded and hashed successfully",
	}); werr != nil {
		slog.Error("write upload response", "error", werr)
	}
}

func formValue(part io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(part, 4096))
	if err != nil {
		return ""
	}
	return string(raw)
}

// handleRegisterArtifact copies (or moves) an agent-host file into the cache
// and hashes it — SHI's add-file picker flow for Direct-mode installs where
// the browser and the agent share a machine.
func (s *Server) handleRegisterArtifact(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path     string `json:"path"`
		Role     string `json:"role"`
		Kind     string `json:"kind"`
		Filename string `json:"filename"`
		Move     bool   `json:"move"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	source, err := safepath.CleanAbs(body.Path)
	if err != nil {
		taskError(w, http.StatusBadRequest, "path is not usable")
		return
	}
	if info, serr := os.Stat(source); serr != nil || info.IsDir() {
		taskError(w, http.StatusBadRequest, "path does not name a file on the agent host")
		return
	}
	filename := body.Filename
	if filename == "" {
		filename = filepath.Base(source)
	}
	if !assets.ValidRole(body.Role) || !assets.ValidKind(body.Kind) || !assets.ValidFilename(filename) {
		taskError(w, http.StatusBadRequest, "role, kind, or filename is not usable")
		return
	}

	artifact, err := s.assets.Ingest(r.Context(), body.Role, body.Kind, filename, source, body.Move)
	if err != nil {
		slog.Error("artifact registration failed", "path", source, "error", err)
		taskError(w, http.StatusInternalServerError, "Registration failed: "+err.Error())
		return
	}
	slog.Info("artifact registered", "role", artifact.Role, "kind", artifact.Kind,
		"filename", artifact.Filename, "sha256", artifact.SHA256,
		"by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"artifact": artifact,
		"verified": artifact.Verified(),
		"message":  "File registered and hashed successfully",
	}); werr != nil {
		slog.Error("write register response", "error", werr)
	}
}

// handleDeleteArtifact removes a registry row (?delete_file=true removes the
// cached file too).
func (s *Server) handleDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	deleteFile := r.URL.Query().Get("delete_file") == "true"
	if derr := s.assets.Delete(r.Context(), id, deleteFile); derr != nil {
		if errors.Is(derr, assets.ErrNotFound) {
			taskError(w, http.StatusNotFound, "Artifact not found")
			return
		}
		slog.Error("delete artifact", "id", id, "error", derr)
		taskError(w, http.StatusInternalServerError, "Failed to delete artifact")
		return
	}
	slog.Info("artifact deleted", "id", id, "delete_file", deleteFile,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"message": "Artifact deleted successfully",
	})
}
