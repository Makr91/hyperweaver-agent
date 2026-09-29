package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

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

type artifactStorageLocation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type artifactDocument struct {
	ID                int64                    `json:"id"`
	StorageLocationID string                   `json:"storage_location_id"`
	Filename          string                   `json:"filename"`
	Path              string                   `json:"path"`
	Size              int64                    `json:"size"`
	FileType          string                   `json:"file_type"`
	Extension         string                   `json:"extension"`
	MimeType          string                   `json:"mime_type"`
	Checksum          string                   `json:"checksum"`
	ChecksumAlgorithm string                   `json:"checksum_algorithm"`
	ChecksumVerified  *bool                    `json:"checksum_verified"`
	FileExists        bool                     `json:"file_exists"`
	Verified          bool                     `json:"verified"`
	DiscoveredAt      time.Time                `json:"discovered_at"`
	LastVerified      *time.Time               `json:"last_verified"`
	UpdatedAt         time.Time                `json:"updatedAt"`
	Role              string                   `json:"role,omitempty"`
	ExpectedSHA256    string                   `json:"expected_sha256,omitempty"`
	Version           string                   `json:"version,omitempty"`
	SourceURL         string                   `json:"source_url,omitempty"`
	StorageLocation   *artifactStorageLocation `json:"storage_location,omitempty"`
}

// artifactJSON is the wire artifact document: zoneweaver's Artifact schema
// (checksum/file_type/extension/mime_type/checksum_verified/storage_location)
// merged with the SHI extras the struct itself carries.
func artifactJSON(a *assets.Artifact, location *assets.Location) artifactDocument {
	doc := artifactDocument{
		ID:                a.ID,
		StorageLocationID: a.LocationID,
		Filename:          a.Filename,
		Path:              a.Path,
		Size:              a.Size,
		FileType:          a.Kind,
		Extension:         a.Extension(),
		MimeType:          a.MimeType(),
		Checksum:          a.SHA256,
		ChecksumAlgorithm: "sha256",
		ChecksumVerified:  a.ChecksumVerified(),
		FileExists:        a.Exists,
		Verified:          a.Verified(),
		DiscoveredAt:      a.CreatedAt,
		LastVerified:      a.VerifiedAt,
		UpdatedAt:         a.UpdatedAt,
		Role:              a.Role,
		ExpectedSHA256:    a.ExpectedSHA256,
		Version:           a.Version,
		SourceURL:         a.SourceURL,
	}
	if location != nil {
		doc.StorageLocation = &artifactStorageLocation{
			ID:   location.ID,
			Name: location.Name,
			Path: location.Path,
			Type: location.Type,
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
