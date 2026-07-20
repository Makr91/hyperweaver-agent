package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// ---- storage paths ----

// storagePathsResponse is GET /artifacts/storage/paths's answer.
type storagePathsResponse struct {
	Paths      []*assets.Location `json:"paths"`
	TotalPaths int                `json:"total_paths"`
}

// handleListStoragePaths: GET /artifacts/storage/paths (?type, ?enabled).
//
//	@Summary		List storage locations
//	@Description	Minimum role: viewer. Every storage location — the five built-ins plus config/API-added paths. 503 when artifact_storage.enabled is false (every /artifacts endpoint shares this gate).
//	@Tags			Artifacts
//	@Produce		json
//	@Param			type	query	string	false	"Filter by location type"
//	@Param			enabled	query	bool	false	"Filter by enabled state"
//	@Success		200	{object}	storagePathsResponse	"Storage locations"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/storage/paths [get]
func (s *Server) handleListStoragePaths(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := assets.LocationFilter{Type: query.Get("type")}
	if raw := query.Get("enabled"); raw != "" {
		enabled := raw == "true"
		filter.Enabled = &enabled
	}
	locations, err := s.assets.ListLocations(r.Context(), &filter)
	if err != nil {
		slog.Error("list storage paths", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve storage paths")
		return
	}
	writeJSON(w, storagePathsResponse{
		Paths:      locations,
		TotalPaths: len(locations),
	})
}

// persistConfigPaths writes the runtime paths list back into config.yaml
// (zoneweaver's updateConfigWithNewPath — the config stays the source of
// truth across restarts). Failure only logs: the location exists in the
// database either way.
func (s *Server) persistConfigPaths() {
	section := map[string]any{
		"enabled":       s.cfg.ArtifactStorage.Enabled,
		"dir":           s.cfg.ArtifactStorage.Dir,
		"max_upload_gb": s.cfg.ArtifactStorage.MaxUploadGB,
		"download": map[string]any{
			"timeout_seconds": s.cfg.ArtifactStorage.Download.TimeoutSeconds,
		},
		"scanning": map[string]any{
			"periodic_scan_interval": s.cfg.ArtifactStorage.Scanning.PeriodicScanInterval,
			"supported_extensions":   s.cfg.ArtifactStorage.Scanning.SupportedExtensions,
		},
		"paths": s.cfg.ArtifactStorage.Paths,
	}
	if err := s.cfg.MergeAndSave(map[string]any{"artifact_storage": section}); err != nil {
		slog.Error("persist artifact_storage paths to config", "error", err)
	}
}

// createStoragePathRequest is POST /artifacts/storage/paths's body.
type createStoragePathRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// Type is one of iso, image, installer, fixpack, hotfix.
	Type    string `json:"type"`
	Enabled *bool  `json:"enabled"`
}

// storageLocationResponse is the create/update storage-location answer.
type storageLocationResponse struct {
	Success         bool             `json:"success"`
	Message         string           `json:"message"`
	StorageLocation *assets.Location `json:"storage_location"`
}

// handleCreateStoragePath: POST /artifacts/storage/paths.
//
//	@Summary		Add a storage location
//	@Description	Minimum role: operator. Creates the directory (when absent), the location row, persists the entry into config.yaml artifact_storage.paths[] (so it survives restarts), and queues an initial scan.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	createStoragePathRequest	true	"New location name, path, type, and enabled flag"
//	@Success		201	{object}	storageLocationResponse	"Location created"
//	@Failure		400	"Missing name/path/type, invalid type, or directory not creatable"
//	@Failure		409	"Path already registered ({error, existing_location})"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/storage/paths [post]
func (s *Server) handleCreateStoragePath(w http.ResponseWriter, r *http.Request) {
	var body createStoragePathRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" || body.Path == "" || body.Type == "" {
		taskError(w, http.StatusBadRequest, "name, path, and type are required")
		return
	}
	if !assets.ValidKind(body.Type) {
		taskError(w, http.StatusBadRequest, "type must be one of iso, image, installer, fixpack, hotfix")
		return
	}
	clean, err := safepath.CleanAbs(body.Path)
	if err != nil {
		taskError(w, http.StatusBadRequest, "path is not usable")
		return
	}
	if existing, ferr := s.assets.FindLocationByPath(r.Context(), clean); ferr == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "Storage path already exists: " + clean,
			"existing_location": map[string]any{
				"id": existing.ID, "name": existing.Name, "type": existing.Type,
			},
		})
		return
	}
	if merr := os.MkdirAll(clean, 0o750); merr != nil {
		taskError(w, http.StatusBadRequest, "Cannot create storage directory: "+merr.Error())
		return
	}

	enabled := body.Enabled == nil || *body.Enabled
	location, err := s.assets.CreateLocation(r.Context(), &assets.NewLocation{
		Name: body.Name, Path: clean, Type: body.Type, Enabled: enabled, Source: "config",
	})
	if err != nil {
		slog.Error("create storage path", "path", clean, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create storage path")
		return
	}

	// Persist into config.yaml so the location survives restarts.
	s.cfg.ArtifactStorage.Paths = append(s.cfg.ArtifactStorage.Paths, config.ArtifactPathConfig{
		Name: body.Name, Path: clean, Type: body.Type, Enabled: enabled,
	})
	s.persistConfigPaths()

	// Initial scan (background task — user-visible, zoneweaver's rule).
	if enabled {
		raw, merr := json.Marshal(assets.ScanTaskMetadata{LocationID: location.ID})
		if merr == nil {
			metadata := string(raw)
			if _, terr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
				MachineName: "artifact",
				Operation:   assets.OpScan,
				Priority:    tasks.PriorityBackground,
				CreatedBy:   auth.FromContext(r.Context()).Name,
				Metadata:    &metadata,
			}); terr != nil {
				slog.Warn("initial scan task for new storage path failed to queue", "error", terr)
			}
		}
	}

	slog.Info("storage path created", "name", body.Name, "path", clean, "type", body.Type,
		"by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(storageLocationResponse{
		Success:         true,
		Message:         "Storage path '" + body.Name + "' created successfully",
		StorageLocation: location,
	}); werr != nil {
		slog.Error("write create storage path response", "error", werr)
	}
}

// updateStoragePathRequest is PUT /artifacts/storage/paths/{id}'s body
// (name and enabled only — path/type are identity).
type updateStoragePathRequest struct {
	Name    *string `json:"name"`
	Enabled *bool   `json:"enabled"`
}

// handleUpdateStoragePath: PUT /artifacts/storage/paths/{id} (name, enabled).
//
//	@Summary		Update a storage location
//	@Description	Minimum role: operator. name and enabled only (zoneweaver's contract — path/type are identity). Mirrored into the config.yaml entry.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			id		path	string	true	"Storage location id"
//	@Param			body	body	updateStoragePathRequest	true	"New name and/or enabled state"
//	@Success		200	{object}	storageLocationResponse	"Location updated"
//	@Failure		404	"Storage path not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/storage/paths/{id} [put]
func (s *Server) handleUpdateStoragePath(w http.ResponseWriter, r *http.Request) {
	var body updateStoragePathRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	location, err := s.assets.UpdateLocation(r.Context(), r.PathValue("id"), body.Name, body.Enabled)
	if errors.Is(err, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage path not found")
		return
	}
	if err != nil {
		slog.Error("update storage path", "id", r.PathValue("id"), "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update storage path")
		return
	}

	// Mirror the change onto the config entry (matched by path).
	for i := range s.cfg.ArtifactStorage.Paths {
		if s.cfg.ArtifactStorage.Paths[i].Path == location.Path {
			s.cfg.ArtifactStorage.Paths[i].Name = location.Name
			s.cfg.ArtifactStorage.Paths[i].Enabled = location.Enabled
			s.persistConfigPaths()
			break
		}
	}

	writeJSON(w, storageLocationResponse{
		Success:         true,
		Message:         "Storage path '" + location.Name + "' updated successfully",
		StorageLocation: location,
	})
}

// deleteStoragePathRequest is DELETE /artifacts/storage/paths/{id}'s optional body.
type deleteStoragePathRequest struct {
	// Recursive deletes the folder's contents (default true).
	Recursive *bool `json:"recursive"`
	// RemoveDBRecords removes the artifact rows (default true).
	RemoveDBRecords *bool `json:"remove_db_records"`
	// Force keeps going past individual removal errors.
	Force bool `json:"force"`
}

// handleDeleteStoragePath: DELETE /artifacts/storage/paths/{id} — queues the
// deletion task (contents + rows + the location row). Built-in locations
// never delete: the startup sync would just recreate them.
//
//	@Summary		Delete a storage location
//	@Description	Minimum role: operator. Drops the config entry immediately and queues an artifact_delete_folder task: contents removed (recursive, the folder itself stays), rows removed, then the location row. Built-in locations are REFUSED (the startup sync would recreate them — disable instead).
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			id		path	string	true	"Storage location id"
//	@Param			body	body	deleteStoragePathRequest	false	"Deletion options"
//	@Success		202	"Deletion task queued ({success, task_id, status, message})"
//	@Failure		400	"Built-in location"
//	@Failure		404	"Storage path not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/artifacts/storage/paths/{id} [delete]
func (s *Server) handleDeleteStoragePath(w http.ResponseWriter, r *http.Request) {
	var body deleteStoragePathRequest
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	location, err := s.assets.GetLocation(r.Context(), r.PathValue("id"))
	if errors.Is(err, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage path not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load storage path")
		return
	}
	if location.Source == "builtin" {
		taskError(w, http.StatusBadRequest, "Built-in locations cannot be deleted (disable instead)")
		return
	}

	// Drop the config entry now — the executor removes rows and files.
	kept := s.cfg.ArtifactStorage.Paths[:0]
	for _, entry := range s.cfg.ArtifactStorage.Paths {
		if entry.Path != location.Path {
			kept = append(kept, entry)
		}
	}
	if len(kept) != len(s.cfg.ArtifactStorage.Paths) {
		s.cfg.ArtifactStorage.Paths = kept
		s.persistConfigPaths()
	}

	meta := assets.DeleteFolderMetadata{
		LocationID:      location.ID,
		Recursive:       body.Recursive == nil || *body.Recursive,
		RemoveDBRecords: body.RemoveDBRecords == nil || *body.RemoveDBRecords,
		Force:           body.Force,
	}
	s.queueArtifactTask(w, r, assets.OpDeleteFolder, tasks.PriorityMedium, meta,
		"Deletion task created for storage path '"+location.Name+"'")
}
