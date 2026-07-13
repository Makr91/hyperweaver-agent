package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
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

// ---- storage paths ----

// handleListStoragePaths: GET /artifacts/storage/paths (?type, ?enabled).
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
	writeJSON(w, map[string]any{
		"paths":       locations,
		"total_paths": len(locations),
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

// handleCreateStoragePath: POST /artifacts/storage/paths.
func (s *Server) handleCreateStoragePath(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		Path    string `json:"path"`
		Type    string `json:"type"`
		Enabled *bool  `json:"enabled"`
	}
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
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":          true,
		"message":          "Storage path '" + body.Name + "' created successfully",
		"storage_location": location,
	}); werr != nil {
		slog.Error("write create storage path response", "error", werr)
	}
}

// handleUpdateStoragePath: PUT /artifacts/storage/paths/{id} (name, enabled).
func (s *Server) handleUpdateStoragePath(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
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

	writeJSON(w, map[string]any{
		"success":          true,
		"message":          "Storage path '" + location.Name + "' updated successfully",
		"storage_location": location,
	})
}

// handleDeleteStoragePath: DELETE /artifacts/storage/paths/{id} — queues the
// deletion task (contents + rows + the location row). Built-in locations
// never delete: the startup sync would just recreate them.
func (s *Server) handleDeleteStoragePath(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Recursive       *bool `json:"recursive"`
		RemoveDBRecords *bool `json:"remove_db_records"`
		Force           bool  `json:"force"`
	}
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

// ---- artifacts ----

// handleListArtifacts: GET /artifacts (?type, ?storage_path_id, ?role,
// ?search, ?limit, ?offset, ?sort_by, ?sort_order).
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	if limit <= 0 {
		limit = 50
	}
	filter := assets.ListFilter{
		Kind:       query.Get("type"),
		LocationID: query.Get("storage_path_id"),
		Role:       query.Get("role"),
		Search:     query.Get("search"),
		SortBy:     query.Get("sort_by"),
		SortOrder:  query.Get("sort_order"),
		Limit:      limit,
		Offset:     offset,
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
	total, err := s.assets.Count(r.Context(), &filter)
	if err != nil {
		slog.Error("count artifacts", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve artifacts")
		return
	}

	index := s.locationIndex(r)
	documents := make([]map[string]any, 0, len(list))
	for _, artifact := range list {
		documents = append(documents, artifactJSON(artifact, index[artifact.LocationID]))
	}
	writeJSON(w, map[string]any{
		"artifacts": documents,
		"pagination": map[string]any{
			"total":    total,
			"limit":    limit,
			"offset":   offset,
			"has_more": offset+limit < total,
		},
	})
}

// handleListISOArtifacts / handleListImageArtifacts: the typed conveniences.
func (s *Server) handleListISOArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("type", assets.KindISO)
	r.URL.RawQuery = q.Encode()
	s.handleListArtifacts(w, r)
}

func (s *Server) handleListImageArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("type", assets.KindImage)
	r.URL.RawQuery = q.Encode()
	s.handleListArtifacts(w, r)
}

// handleArtifactDetails: GET /artifacts/{id}.
func (s *Server) handleArtifactDetails(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	artifact, err := s.assets.Get(r.Context(), id)
	if errors.Is(err, assets.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to retrieve artifact details")
		return
	}
	var location *assets.Location
	if artifact.LocationID != "" {
		location, _ = s.assets.GetLocation(r.Context(), artifact.LocationID)
	}
	writeJSON(w, artifactJSON(artifact, location))
}

// handleArtifactStats: GET /artifacts/stats.
func (s *Server) handleArtifactStats(w http.ResponseWriter, r *http.Request) {
	locations, err := s.assets.ListLocations(r.Context(), &assets.LocationFilter{})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to retrieve statistics")
		return
	}

	byType := map[string]map[string]any{}
	storageLocations := make([]map[string]any, 0, len(locations))
	totals := map[string]any{}
	totalArtifacts, totalSize, enabledCount := int64(0), int64(0), 0
	for _, location := range locations {
		if location.Enabled {
			enabledCount++
		}
		totalArtifacts += location.FileCount
		totalSize += location.TotalSize
		entry := byType[location.Type]
		if entry == nil {
			entry = map[string]any{"count": int64(0), "total_size": int64(0), "locations": 0}
			byType[location.Type] = entry
		}
		entry["count"] = entry["count"].(int64) + location.FileCount
		entry["total_size"] = entry["total_size"].(int64) + location.TotalSize
		entry["locations"] = entry["locations"].(int) + 1
		storageLocations = append(storageLocations, map[string]any{
			"id": location.ID, "name": location.Name, "path": location.Path,
			"type": location.Type, "enabled": location.Enabled,
			"file_count": location.FileCount, "total_size": location.TotalSize,
			"last_scan": location.LastScanAt,
		})
	}
	totals["locations"] = len(locations)
	totals["enabled_locations"] = enabledCount
	totals["total_artifacts"] = totalArtifacts
	totals["total_size"] = totalSize

	// Recent activity from the task queue (zoneweaver's 24h window).
	since := time.Now().Add(-24 * time.Hour)
	countTasks := func(operation, status string) int {
		n, cerr := s.tasks.Store().Count(r.Context(), &tasks.ListFilter{
			Operation: operation, Status: status, Since: &since,
		})
		if cerr != nil {
			return 0
		}
		return n
	}
	activity := map[string]any{
		"downloads_last_24h": countTasks(assets.OpDownload, tasks.StatusCompleted),
		"uploads_last_24h":   countTasks(assets.OpUpload, tasks.StatusCompleted),
		"failed_operations_last_24h": countTasks(assets.OpDownload, tasks.StatusFailed) +
			countTasks(assets.OpUpload, tasks.StatusFailed),
	}

	writeJSON(w, map[string]any{
		"by_type":           byType,
		"storage_locations": storageLocations,
		"totals":            totals,
		"recent_activity":   activity,
	})
}

// handleArtifactServiceStatus: GET /artifacts/service/status.
func (s *Server) handleArtifactServiceStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.artifactSvc.Status())
}

// ---- transfers, downloads, uploads ----

// handleArtifactAction: POST /artifacts/{id}/{action} — move and copy share
// one pattern (separate literal patterns conflict with /artifacts/upload/
// {taskId} and panic ServeMux at registration).
func (s *Server) handleArtifactAction(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("action") {
	case "move":
		s.queueTransfer(w, r, assets.OpMove, "Artifact move task created successfully.")
	case "copy":
		s.queueTransfer(w, r, assets.OpCopy, "Artifact copy task created successfully.")
	default:
		taskError(w, http.StatusNotFound, "Unknown artifact action (move or copy)")
	}
}

func (s *Server) queueTransfer(w http.ResponseWriter, r *http.Request, operation, message string) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	var body struct {
		DestinationID string `json:"destination_storage_location_id"`
	}
	if derr := decodeBody(r, &body); derr != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.DestinationID == "" {
		taskError(w, http.StatusBadRequest, "destination_storage_location_id is required")
		return
	}
	if _, gerr := s.assets.Get(r.Context(), id); errors.Is(gerr, assets.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	if _, gerr := s.assets.GetLocation(r.Context(), body.DestinationID); errors.Is(gerr, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	s.queueArtifactTask(w, r, operation, tasks.PriorityMedium,
		assets.TransferMetadata{ArtifactID: id, DestinationID: body.DestinationID}, message)
}

// handleArtifactDownloadFromURL: POST /artifacts/download (async task).
func (s *Server) handleArtifactDownloadFromURL(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL               string `json:"url"`
		StoragePathID     string `json:"storage_path_id"`
		Role              string `json:"role"`
		Filename          string `json:"filename"`
		Checksum          string `json:"checksum"`
		ChecksumAlgorithm string `json:"checksum_algorithm"`
		OverwriteExisting bool   `json:"overwrite_existing"`
		ResourceName      string `json:"resource_name"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.ChecksumAlgorithm != "" && body.ChecksumAlgorithm != "sha256" {
		taskError(w, http.StatusBadRequest, "checksum_algorithm must be sha256 (the system's one algorithm)")
		return
	}
	meta := assets.DownloadMetadata{
		URL: body.URL, LocationID: body.StoragePathID, Role: body.Role,
		Filename: body.Filename, Checksum: body.Checksum,
		OverwriteExisting: body.OverwriteExisting, ResourceName: body.ResourceName,
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	location, err := s.assets.GetLocation(r.Context(), meta.LocationID)
	if errors.Is(err, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load storage location")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}
	if assets.RoleKeyed(location.Type) && !assets.ValidRole(meta.Role) {
		taskError(w, http.StatusBadRequest, "role is required for "+location.Type+" locations")
		return
	}
	s.queueArtifactTask(w, r, assets.OpDownload, tasks.PriorityMedium, meta,
		"Download task created for '"+meta.Filename+"'")
}

// handlePrepareArtifactUpload: POST /artifacts/upload/prepare — mints the
// prepared task and the upload URL (zoneweaver's two-step upload).
func (s *Server) handlePrepareArtifactUpload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Filename          string `json:"filename"`
		Size              int64  `json:"size"`
		StoragePathID     string `json:"storage_path_id"`
		Role              string `json:"role"`
		Checksum          string `json:"checksum"`
		ChecksumAlgorithm string `json:"checksum_algorithm"`
		OverwriteExisting bool   `json:"overwrite_existing"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Filename == "" || body.Size <= 0 || body.StoragePathID == "" {
		taskError(w, http.StatusBadRequest, "filename, size, and storage_path_id are required")
		return
	}
	if !assets.ValidFilename(body.Filename) {
		taskError(w, http.StatusBadRequest, "filename is not usable")
		return
	}
	if body.ChecksumAlgorithm != "" && body.ChecksumAlgorithm != "sha256" {
		taskError(w, http.StatusBadRequest, "checksum_algorithm must be sha256 (the system's one algorithm)")
		return
	}
	maxBytes := int64(s.cfg.ArtifactStorage.MaxUploadGB) << 30
	if body.Size > maxBytes {
		taskError(w, http.StatusBadRequest, fmt.Sprintf(
			"File size exceeds the %dGB upload limit", s.cfg.ArtifactStorage.MaxUploadGB))
		return
	}
	location, err := s.assets.GetLocation(r.Context(), body.StoragePathID)
	if errors.Is(err, assets.ErrLocationNotFound) {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load storage location")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}
	if assets.RoleKeyed(location.Type) && !assets.ValidRole(body.Role) {
		taskError(w, http.StatusBadRequest, "role is required for "+location.Type+" locations")
		return
	}

	raw, err := json.Marshal(assets.UploadMetadata{
		OriginalName: body.Filename, Size: body.Size, LocationID: location.ID,
		Role: body.Role, Checksum: body.Checksum, OverwriteExisting: body.OverwriteExisting,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to prepare upload")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "artifact",
		Operation:   assets.OpUpload,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
		Prepared:    true,
	})
	if err != nil {
		slog.Error("prepare artifact upload", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to prepare upload")
		return
	}
	writeJSON(w, map[string]any{
		"success":    true,
		"task_id":    task.ID,
		"upload_url": "/artifacts/upload/" + task.ID,
		"expires_at": time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
		"storage_location": map[string]any{
			"id": location.ID, "name": location.Name, "path": location.Path,
		},
	})
}

// handleUploadArtifactToTask: POST /artifacts/upload/{taskId} — streams the
// multipart file to its final location and flips the prepared task to
// pending; the artifact_upload executor hashes and registers it.
func (s *Server) handleUploadArtifactToTask(w http.ResponseWriter, r *http.Request) {
	task, err := s.tasks.Store().Get(r.Context(), r.PathValue("taskId"))
	if errors.Is(err, tasks.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Upload task not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load upload task")
		return
	}
	if task.Operation != assets.OpUpload {
		taskError(w, http.StatusBadRequest, "Invalid task type for upload")
		return
	}
	if task.Status != tasks.StatusPrepared {
		taskError(w, http.StatusBadRequest, "Task is not in prepared state (current: "+task.Status+")")
		return
	}
	var meta assets.UploadMetadata
	if task.Metadata == nil || json.Unmarshal([]byte(*task.Metadata), &meta) != nil {
		taskError(w, http.StatusInternalServerError, "Upload task metadata is unreadable")
		return
	}
	location, err := s.assets.GetLocation(r.Context(), meta.LocationID)
	if err != nil {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(s.cfg.ArtifactStorage.MaxUploadGB)<<30)
	reader, err := r.MultipartReader()
	if err != nil {
		taskError(w, http.StatusBadRequest, "Request must be multipart/form-data")
		return
	}
	landed := false
	var size int64
	for {
		part, perr := reader.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			taskError(w, http.StatusBadRequest, "Malformed multipart body: "+perr.Error())
			return
		}
		if part.FormName() != "file" {
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
			continue
		}
		finalPath, written, lerr := assets.LandUpload(location, meta.Role, meta.OriginalName, part, meta.OverwriteExisting)
		_ = part.Close()
		if lerr != nil {
			taskError(w, http.StatusBadRequest, "File upload failed: "+lerr.Error())
			return
		}
		meta.FinalPath = finalPath
		size = written
		landed = true
		break
	}
	if !landed {
		taskError(w, http.StatusBadRequest, `multipart body carries no "file" part`)
		return
	}

	meta.Size = size
	meta.UploadCompleted = true
	raw, err := json.Marshal(meta)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to update upload task")
		return
	}
	if uerr := s.tasks.Store().UpdateMetadata(r.Context(), task.ID, string(raw)); uerr != nil {
		taskError(w, http.StatusInternalServerError, "Failed to update upload task")
		return
	}
	if ok, qerr := s.tasks.Store().Requeue(r.Context(), task.ID); qerr != nil || !ok {
		taskError(w, http.StatusInternalServerError, "Failed to queue upload processing")
		return
	}

	slog.Info("artifact upload landed", "filename", meta.OriginalName, "task_id", task.ID,
		"by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": "Upload completed for '" + meta.OriginalName + "'",
		"task_id": task.ID,
		"file": map[string]any{
			"name": meta.OriginalName, "size": size, "final_location": meta.FinalPath,
		},
	}); werr != nil {
		slog.Error("write upload response", "error", werr)
	}
}

// handleDownloadArtifactFile: GET /artifacts/{id}/download — streams the
// file to the client.
func (s *Server) handleDownloadArtifactFile(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	artifact, err := s.assets.Get(r.Context(), id)
	if errors.Is(err, assets.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Artifact not found")
		return
	}
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to load artifact")
		return
	}
	if artifact.Path == "" {
		taskError(w, http.StatusNotFound, "Artifact has no file (expectation only)")
		return
	}
	file, err := os.Open(filepath.Clean(artifact.Path))
	if err != nil {
		taskError(w, http.StatusNotFound, "Artifact file not found on disk")
		return
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to read artifact file")
		return
	}

	w.Header().Set("Content-Disposition", `attachment; filename="`+artifact.Filename+`"`)
	w.Header().Set("Content-Type", artifact.MimeType())
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	if _, cerr := io.Copy(w, file); cerr != nil {
		slog.Warn("artifact stream interrupted", "id", id, "error", cerr)
		return
	}
	_ = s.assets.TouchVerified(r.Context(), artifact.ID)
}

// handleScanArtifacts: POST /artifacts/scan (async task).
func (s *Server) handleScanArtifacts(w http.ResponseWriter, r *http.Request) {
	var meta assets.ScanTaskMetadata
	if r.ContentLength > 0 {
		if err := decodeBody(r, &meta); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	message := "Scan task created for all storage locations"
	if meta.LocationID != "" {
		location, err := s.assets.GetLocation(r.Context(), meta.LocationID)
		if errors.Is(err, assets.ErrLocationNotFound) {
			taskError(w, http.StatusNotFound, "Storage location not found")
			return
		}
		if err != nil {
			taskError(w, http.StatusInternalServerError, "Failed to load storage location")
			return
		}
		message = "Scan task created for storage location '" + location.Name + "'"
	} else if meta.Type != "" {
		if !assets.ValidKind(meta.Type) {
			taskError(w, http.StatusBadRequest, "type must be one of iso, image, installer, fixpack, hotfix")
			return
		}
		message = "Scan task created for " + meta.Type + " locations"
	}
	s.queueArtifactTask(w, r, assets.OpScan, tasks.PriorityBackground, meta, message)
}

// handleDeleteArtifactFiles: DELETE /artifacts/files (batch, async task).
func (s *Server) handleDeleteArtifactFiles(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ArtifactIDs []int64 `json:"artifact_ids"`
		DeleteFiles *bool   `json:"delete_files"`
		Force       bool    `json:"force"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if len(body.ArtifactIDs) == 0 {
		taskError(w, http.StatusBadRequest, "artifact_ids array is required and must not be empty")
		return
	}
	meta := assets.DeleteFilesMetadata{
		ArtifactIDs: body.ArtifactIDs,
		DeleteFiles: body.DeleteFiles == nil || *body.DeleteFiles,
		Force:       body.Force,
	}
	s.queueArtifactTask(w, r, assets.OpDeleteFiles, tasks.PriorityMedium, meta,
		fmt.Sprintf("Deletion task created for %d artifact(s)", len(body.ArtifactIDs)))
}

// ---- SHI extras ----

// handleHCLDownload: POST /artifacts/hcl-download — the SHI download-portal
// flow (token exchange with rotation persisted, catalog lookup, verified
// streamed download into the kind's default location).
func (s *Server) handleHCLDownload(w http.ResponseWriter, r *http.Request) {
	var meta assets.HCLDownloadMetadata
	if err := decodeBody(r, &meta); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if err := meta.Validate(); err != nil {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.queueArtifactTask(w, r, assets.OpHCLDownload, tasks.PriorityMedium, meta,
		"HCL download task queued successfully")
}

// handleRegisterArtifact: POST /artifacts/register — copies (or moves) an
// agent-host file into a location and hashes it (SHI's add-file picker for
// Direct mode).
func (s *Server) handleRegisterArtifact(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path          string `json:"path"`
		StoragePathID string `json:"storage_path_id"`
		Type          string `json:"type"`
		Role          string `json:"role"`
		Filename      string `json:"filename"`
		Move          bool   `json:"move"`
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

	var location *assets.Location
	switch {
	case body.StoragePathID != "":
		location, err = s.assets.GetLocation(r.Context(), body.StoragePathID)
	case assets.ValidKind(body.Type):
		location, err = s.assets.DefaultLocation(r.Context(), body.Type)
	default:
		taskError(w, http.StatusBadRequest, "storage_path_id or a valid type is required")
		return
	}
	if err != nil {
		taskError(w, http.StatusNotFound, "Storage location not found")
		return
	}
	if !location.Enabled {
		taskError(w, http.StatusBadRequest, "Storage location is disabled")
		return
	}

	filename := body.Filename
	if filename == "" {
		filename = filepath.Base(source)
	}
	if !assets.ValidFilename(filename) {
		taskError(w, http.StatusBadRequest, "filename is not usable")
		return
	}
	if assets.RoleKeyed(location.Type) && !assets.ValidRole(body.Role) {
		taskError(w, http.StatusBadRequest, "role is required for "+location.Type+" locations")
		return
	}

	artifact, err := s.assets.Ingest(r.Context(), location, body.Role, filename, source, body.Move)
	if err != nil {
		slog.Error("artifact registration failed", "path", source, "error", err)
		taskError(w, http.StatusInternalServerError, "Registration failed: "+err.Error())
		return
	}
	slog.Info("artifact registered", "filename", artifact.Filename, "sha256", artifact.SHA256,
		"location", location.Name, "by", auth.FromContext(r.Context()).Name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":  true,
		"artifact": artifactJSON(artifact, location),
		"message":  "File registered and hashed successfully",
	}); werr != nil {
		slog.Error("write register response", "error", werr)
	}
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
