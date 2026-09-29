package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// ---- artifacts ----

// artifactPagination is the /artifacts list paging block.
type artifactPagination struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

// artifactListResponse is GET /artifacts's answer. Each row keeps the
// artifactJSON document shape (the zoneweaver Artifact fields plus the
// computed extension/mime_type/checksum_verified/verified/storage_location).
type artifactListResponse struct {
	Artifacts  []artifactDocument `json:"artifacts"`
	Pagination artifactPagination `json:"pagination"`
}

type artifactTypeTotals struct {
	Count     int64 `json:"count"`
	TotalSize int64 `json:"total_size"`
	Locations int   `json:"locations"`
}

type artifactStatsLocation struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Path      string     `json:"path"`
	Type      string     `json:"type"`
	Enabled   bool       `json:"enabled"`
	FileCount int64      `json:"file_count"`
	TotalSize int64      `json:"total_size"`
	LastScan  *time.Time `json:"last_scan"`
}

type artifactStatsTotals struct {
	Locations        int   `json:"locations"`
	EnabledLocations int   `json:"enabled_locations"`
	TotalArtifacts   int64 `json:"total_artifacts"`
	TotalSize        int64 `json:"total_size"`
}

type artifactStatsActivity struct {
	DownloadsLast24h        int `json:"downloads_last_24h"`
	UploadsLast24h          int `json:"uploads_last_24h"`
	FailedOperationsLast24h int `json:"failed_operations_last_24h"`
}

type artifactStatsResponse struct {
	ByType           map[string]artifactTypeTotals `json:"by_type"`
	StorageLocations []artifactStatsLocation       `json:"storage_locations"`
	Totals           artifactStatsTotals           `json:"totals"`
	RecentActivity   artifactStatsActivity         `json:"recent_activity"`
}

// handleListArtifacts: GET /artifacts (?type, ?storage_path_id, ?role,
// ?search, ?limit, ?offset, ?sort_by, ?sort_order).
//
//	@Summary		List artifacts
//	@Description	Minimum role: viewer. Every registry row — present files and expectation-only entries — with zoneweaver's filtering and paging.
//	@Tags			Artifacts
//	@Produce		json
//	@Param			type			query	string	false	"Filter by artifact type"
//	@Param			storage_path_id	query	string	false	"Filter by storage location id"
//	@Param			role			query	string	false	"Installer-family role filter"
//	@Param			search			query	string	false	"Filename substring"
//	@Param			exists			query	bool	false	"file_exists filter"
//	@Param			limit			query	int		false	"Maximum artifacts to return"
//	@Param			offset			query	int		false	"Pagination offset"
//	@Param			sort_by			query	string	false	"Sort field"
//	@Param			sort_order		query	string	false	"Sort direction"
//	@Success		200	{object}	artifactListResponse	"Artifacts with pagination"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts [get]
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
	documents := make([]artifactDocument, 0, len(list))
	for _, artifact := range list {
		documents = append(documents, artifactJSON(artifact, index[artifact.LocationID]))
	}
	writeJSON(w, artifactListResponse{
		Artifacts: documents,
		Pagination: artifactPagination{
			Total:   total,
			Limit:   limit,
			Offset:  offset,
			HasMore: offset+limit < total,
		},
	})
}

// handleListISOArtifacts / handleListImageArtifacts: the typed conveniences.
//
//	@Summary		List ISO artifacts
//	@Description	Minimum role: viewer. GET /api/artifacts pinned to type=iso — the create wizard's ISO-picker feed (cdroms[].iso names entries by filename). Same query parameters minus type.
//	@Tags			Artifacts
//	@Produce		json
//	@Success		200	"ISO artifacts (the /api/artifacts list shape)"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/iso [get]
func (s *Server) handleListISOArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("type", assets.KindISO)
	r.URL.RawQuery = q.Encode()
	s.handleListArtifacts(w, r)
}

// handleListImageArtifacts pins the /artifacts list to type=image.
//
//	@Summary		List image artifacts
//	@Description	Minimum role: viewer. GET /api/artifacts pinned to type=image. Same query parameters minus type.
//	@Tags			Artifacts
//	@Produce		json
//	@Success		200	"Image artifacts (the /api/artifacts list shape)"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/image [get]
func (s *Server) handleListImageArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("type", assets.KindImage)
	r.URL.RawQuery = q.Encode()
	s.handleListArtifacts(w, r)
}

// handleArtifactDetails: GET /artifacts/{id}.
//
//	@Summary		Artifact details
//	@Description	Minimum role: viewer.
//	@Tags			Artifacts
//	@Produce		json
//	@Param			id	path	int	true	"Artifact id"
//	@Success		200	{object}	assets.Artifact	"The artifact"
//	@Failure		404	"Artifact not found"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/{id} [get]
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
//
//	@Summary		Artifact statistics
//	@Description	Minimum role: viewer. Totals per type, per-location summaries, and 24h task activity.
//	@Tags			Artifacts
//	@Produce		json
//	@Success		200	{object}	artifactStatsResponse	"Statistics"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/stats [get]
func (s *Server) handleArtifactStats(w http.ResponseWriter, r *http.Request) {
	locations, err := s.assets.ListLocations(r.Context(), &assets.LocationFilter{})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to retrieve statistics")
		return
	}

	byType := map[string]artifactTypeTotals{}
	storageLocations := make([]artifactStatsLocation, 0, len(locations))
	totalArtifacts, totalSize, enabledCount := int64(0), int64(0), 0
	for _, location := range locations {
		if location.Enabled {
			enabledCount++
		}
		totalArtifacts += location.FileCount
		totalSize += location.TotalSize
		entry := byType[location.Type]
		entry.Count += location.FileCount
		entry.TotalSize += location.TotalSize
		entry.Locations++
		byType[location.Type] = entry
		storageLocations = append(storageLocations, artifactStatsLocation{
			ID: location.ID, Name: location.Name, Path: location.Path,
			Type: location.Type, Enabled: location.Enabled,
			FileCount: location.FileCount, TotalSize: location.TotalSize,
			LastScan: location.LastScanAt,
		})
	}
	totals := artifactStatsTotals{
		Locations:        len(locations),
		EnabledLocations: enabledCount,
		TotalArtifacts:   totalArtifacts,
		TotalSize:        totalSize,
	}

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
	activity := artifactStatsActivity{
		DownloadsLast24h: countTasks(assets.OpDownload, tasks.StatusCompleted),
		UploadsLast24h:   countTasks(assets.OpUpload, tasks.StatusCompleted),
		FailedOperationsLast24h: countTasks(assets.OpDownload, tasks.StatusFailed) +
			countTasks(assets.OpUpload, tasks.StatusFailed),
	}

	writeJSON(w, artifactStatsResponse{
		ByType:           byType,
		StorageLocations: storageLocations,
		Totals:           totals,
		RecentActivity:   activity,
	})
}

// handleArtifactServiceStatus: GET /artifacts/service/status.
//
//	@Summary		Storage service status
//	@Description	Minimum role: viewer. The scan service's state (zoneweaver's getStatus shape): running/initialized/scanning flags, config summary, scan-run stats, active intervals.
//	@Tags			Artifacts
//	@Produce		json
//	@Success		200	{object}	assets.ServiceStatus	"Service status"
//	@Failure		503	"Artifact storage is disabled"
//	@Router			/api/artifacts/service/status [get]
func (s *Server) handleArtifactServiceStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.artifactSvc.Status())
}
