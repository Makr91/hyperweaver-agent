package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// ---- storage paths ----

// storagePathsResponse is GET /api/artifacts/storage/paths's answer.
type storagePathsResponse struct {
	Paths      []*assets.Location `json:"paths"`
	TotalPaths int                `json:"total_paths"`
}

// handleListStoragePaths: GET /api/artifacts/storage/paths (?type, ?enabled).
//
//	@Summary		List storage locations
//	@Description	Minimum role: viewer. Every storage location — the five built-ins plus config/API-added paths. 503 when artifact_storage.enabled is false (every /api/artifacts endpoint shares this gate).
//	@Tags			Artifacts
//	@Produce		json
//	@Param			type	query	string	false	"Filter by location type"
//	@Param			enabled	query	bool	false	"Filter by enabled state"
//	@Success		200	{object}	storagePathsResponse	"Storage locations"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/storage/paths [get]
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

// persistConfigPaths writes the artifact_storage section back into the
// storage configuration file (zoneweaver's updateConfigWithNewPath — the
// file stays the source of truth across restarts). Failure only logs: the
// location exists in the database either way.
func (s *Server) persistConfigPaths() {
	if err := s.cfg.MergeAndSave(map[string]any{"artifact_storage": s.cfg.ArtifactStorage}); err != nil {
		slog.Error("persist artifact_storage paths to config", "error", err)
	}
}

func (s *Server) artifactPathID(name string) string {
	id := strings.Trim(storagePathSlug.ReplaceAllString(strings.ToLower(name), "_"), "_")
	if id == "" || !config.ValidStoragePathID(id) {
		id = "path"
	}
	candidate := id
	for n := 2; ; n++ {
		if _, taken := s.cfg.ArtifactStorage.Paths[candidate]; !taken {
			return candidate
		}
		candidate = id + "_" + strconv.Itoa(n)
	}
}

func (s *Server) artifactPathIDByPath(path string) string {
	for id, entry := range s.cfg.ArtifactStorage.Paths {
		if entry.Path == path {
			return id
		}
	}
	return ""
}

// createStoragePathRequest is POST /api/artifacts/storage/paths's body.
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

// handleCreateStoragePath: POST /api/artifacts/storage/paths.
//
//	@Summary		Add a storage location
//	@Description	Minimum role: operator. Creates the directory (when absent), the location row, persists the entry into the storage configuration file under artifact_storage.paths keyed by an id derived from the name (so it survives restarts), and queues an initial scan.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			body	body	createStoragePathRequest	true	"New location name, path, type, and enabled flag"
//	@Success		201	{object}	storageLocationResponse	"Location created"
//	@Failure		400	{object}	problem.Body	"Unreadable body"
//	@Failure		422	{object}	problem.Body	"name, path or type missing (required); type outside iso, image, installer, fixpack, hotfix (enum at /type); path not absolute (pattern absolutePath at /path); directory not creatable (writable at /path)"
//	@Failure		409	{object}	problem.Body	"Path already registered (unique at /path); existing_location carries the row"
//	@Failure		503	{object}	problem.Body	"Artifact storage is disabled"
//	@Router			/api/artifacts/storage/paths [post]
func (s *Server) handleCreateStoragePath(w http.ResponseWriter, r *http.Request) {
	var body createStoragePathRequest
	if err := decodeBody(r, &body); err != nil {
		problem.BadRequest(w)
		return
	}
	failures := []problem.Error{}
	if body.Name == "" {
		failures = append(failures, problem.Required("/name"))
	}
	if body.Path == "" {
		failures = append(failures, problem.Required("/path"))
	}
	switch {
	case body.Type == "":
		failures = append(failures, problem.Required("/type"))
	case !assets.ValidKind(body.Type):
		failures = append(failures, problem.Enum("/type", "iso", "image", "installer", "fixpack", "hotfix"))
	}
	clean, err := safepath.CleanAbs(body.Path)
	if err != nil && body.Path != "" {
		failures = append(failures, problem.Pattern("/path", "absolutePath"))
	}
	if len(failures) > 0 {
		problem.Invalid(w, failures...)
		return
	}
	if existing, ferr := s.assets.FindLocationByPath(r.Context(), clean); ferr == nil {
		problem.Send(w, http.StatusConflict, "conflict", "", "Storage path already exists: "+clean,
			[]problem.Error{problem.Unique("/path", "artifact storage paths")},
			map[string]any{"existing_location": map[string]any{
				"id": existing.ID, "name": existing.Name, "type": existing.Type,
			}})
		return
	}
	if merr := os.MkdirAll(clean, 0o750); merr != nil {
		failure := problem.Rule("/path", "writable", map[string]any{"user": ""})
		failure.Detail = "Cannot create storage directory: " + merr.Error()
		problem.Invalid(w, failure)
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

	if s.cfg.ArtifactStorage.Paths == nil {
		s.cfg.ArtifactStorage.Paths = map[string]config.ArtifactPathConfig{}
	}
	s.cfg.ArtifactStorage.Paths[s.artifactPathID(body.Name)] = config.ArtifactPathConfig{
		DisplayName: body.Name, Path: clean, Type: body.Type, Enabled: enabled,
	}
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

// updateStoragePathRequest is PUT /api/artifacts/storage/paths/{id}'s body
// (name and enabled only — path/type are identity).
type updateStoragePathRequest struct {
	Name    *string `json:"name"`
	Enabled *bool   `json:"enabled"`
}

// handleUpdateStoragePath: PUT /api/artifacts/storage/paths/{id} (name, enabled).
//
//	@Summary		Update a storage location
//	@Description	Minimum role: operator. name and enabled only (zoneweaver's contract — path/type are identity). Mirrored into the storage configuration file's entry.
//	@Tags			Artifacts
//	@Accept			json
//	@Produce		json
//	@Param			id		path	string	true	"Storage location id"
//	@Param			body	body	updateStoragePathRequest	true	"New name and/or enabled state"
//	@Success		200	{object}	storageLocationResponse	"Location updated"
//	@Failure		404	"Storage path not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/storage/paths/{id} [put]
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
	if id := s.artifactPathIDByPath(location.Path); id != "" {
		entry := s.cfg.ArtifactStorage.Paths[id]
		entry.DisplayName = location.Name
		entry.Enabled = location.Enabled
		s.cfg.ArtifactStorage.Paths[id] = entry
		s.persistConfigPaths()
	}

	writeJSON(w, storageLocationResponse{
		Success:         true,
		Message:         "Storage path '" + location.Name + "' updated successfully",
		StorageLocation: location,
	})
}

// deleteStoragePathRequest is DELETE /api/artifacts/storage/paths/{id}'s optional body.
type deleteStoragePathRequest struct {
	// Recursive deletes the folder's contents (default true).
	Recursive *bool `json:"recursive"`
	// RemoveDBRecords removes the artifact rows (default true).
	RemoveDBRecords *bool `json:"remove_db_records"`
	// Force keeps going past individual removal errors.
	Force bool `json:"force"`
}

// handleDeleteStoragePath: DELETE /api/artifacts/storage/paths/{id} — queues the
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
//	@Router			/api/artifacts/storage/paths/{id} [delete]
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
	if id := s.artifactPathIDByPath(location.Path); id != "" {
		delete(s.cfg.ArtifactStorage.Paths, id)
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
