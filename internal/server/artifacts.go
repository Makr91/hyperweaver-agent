package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The merged artifact surface (the `artifacts` capability token, config-gated
// by artifact_storage.enabled — Mark's ruling 2026-07-09): zoneweaver's
// /artifacts wire contract with iso|image|installer|fixpack|hotfix as the
// type vocabulary, plus the SHI extras (hcl-download, register-local-path,
// hash expectations).

// assetsGate answers 503 while the artifact subsystem is disabled.
func (s *Server) assetsGate(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.ArtifactStorage.Enabled {
			taskError(w, http.StatusServiceUnavailable, "Artifact storage is disabled")
			return
		}
		next(w, r)
	})
}

// artifactJSON is the wire artifact document: zoneweaver's Artifact schema
// (checksum/file_type/extension/mime_type/checksum_verified/storage_location)
// merged with the SHI extras the struct itself carries.
func artifactJSON(a *assets.Artifact, location *assets.Location) map[string]any {
	doc := map[string]any{
		"id":                  a.ID,
		"storage_location_id": a.LocationID,
		"filename":            a.Filename,
		"path":                a.Path,
		"size":                a.Size,
		"file_type":           a.Kind,
		"extension":           a.Extension(),
		"mime_type":           a.MimeType(),
		"checksum":            a.SHA256,
		"checksum_algorithm":  "sha256",
		"checksum_verified":   a.ChecksumVerified(),
		"file_exists":         a.Exists,
		"verified":            a.Verified(),
		"discovered_at":       a.CreatedAt,
		"last_verified":       a.VerifiedAt,
		"updatedAt":           a.UpdatedAt,
	}
	if a.Role != "" {
		doc["role"] = a.Role
	}
	if a.ExpectedSHA256 != "" {
		doc["expected_sha256"] = a.ExpectedSHA256
	}
	if a.Version != "" {
		doc["version"] = a.Version
	}
	if a.SourceURL != "" {
		doc["source_url"] = a.SourceURL
	}
	if location != nil {
		doc["storage_location"] = map[string]any{
			"id":   location.ID,
			"name": location.Name,
			"path": location.Path,
			"type": location.Type,
		}
	}
	return doc
}

// locationByID loads the locations once per request for artifact embedding.
func (s *Server) locationIndex(r *http.Request) map[string]*assets.Location {
	index := map[string]*assets.Location{}
	locations, err := s.assets.ListLocations(r.Context(), &assets.LocationFilter{})
	if err != nil {
		slog.Error("list storage locations", "error", err)
		return index
	}
	for _, location := range locations {
		index[location.ID] = location
	}
	return index
}

// queueArtifactTask creates one artifact task and answers the 202 shape.
func (s *Server) queueArtifactTask(w http.ResponseWriter, r *http.Request,
	operation string, priority int, metadata any, message string,
) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue "+operation+" task")
		return
	}
	metadataStr := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "artifact",
		Operation:   operation,
		Priority:    priority,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadataStr,
	})
	if err != nil {
		slog.Error("queue artifact task", "operation", operation, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue "+operation+" task")
		return
	}
	acceptedTask(w, task.ID, message)
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
