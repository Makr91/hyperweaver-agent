package server

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
)

// Database management endpoints (/database/* — the Node agent's Database
// Management group, adapted to this agent's split-by-contention-domain
// storage): the same statistics, VACUUM, ANALYZE, and manual-cleanup
// operations, applied across every open database file (tasks.sqlite,
// agent.sqlite, and the monitoring files when storage is enabled) instead
// of one. Mutations are admin-only via the central role policy (/database
// is an admin-write prefix).

// DBHandle names one open SQLite database for the /database endpoints.
type DBHandle struct {
	Name   string
	Path   string
	DB     *sql.DB
	Tables []string
}

// tableCountQueries selects the row-count statement per known table — the
// schemas are this agent's own, so every query is a compile-time literal
// (the db-pragma pattern: names never concatenate into SQL text).
var tableCountQueries = map[string]string{
	"tasks":           "SELECT COUNT(*) FROM tasks",
	"machines":        "SELECT COUNT(*) FROM machines",
	"artifacts":       "SELECT COUNT(*) FROM artifacts",
	"cpu_samples":     "SELECT COUNT(*) FROM cpu_samples",
	"memory_samples":  "SELECT COUNT(*) FROM memory_samples",
	"network_samples": "SELECT COUNT(*) FROM network_samples",
}

func fileSize(path string) int64 {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return 0
	}
	return info.Size()
}

// databaseFiles reports the main/-wal/-shm sizes for one database.
func databaseFiles(path string) databaseFileSizes {
	main := fileSize(path)
	wal := fileSize(path + "-wal")
	shm := fileSize(path + "-shm")
	return databaseFileSizes{
		Database: main,
		Wal:      wal,
		Shm:      shm,
		Total:    main + wal + shm,
	}
}

type databaseFileSizes struct {
	Database int64 `json:"database"`
	Wal      int64 `json:"wal"`
	Shm      int64 `json:"shm"`
	Total    int64 `json:"total"`
}

type databaseTableStat struct {
	Name     string `json:"name"`
	RowCount int64  `json:"row_count"`
}

type databaseInternalStats struct {
	PageSize      *int64 `json:"page_size,omitempty"`
	PageCount     *int64 `json:"page_count,omitempty"`
	FreelistCount *int64 `json:"freelist_count,omitempty"`
	FreelistBytes *int64 `json:"freelist_bytes,omitempty"`
}

type databaseStatsDB struct {
	Name        string                `json:"name"`
	StoragePath string                `json:"storage_path"`
	Files       databaseFileSizes     `json:"files"`
	Tables      []databaseTableStat   `json:"tables"`
	TotalTables int                   `json:"total_tables"`
	TotalRows   int64                 `json:"total_rows"`
	Internal    databaseInternalStats `json:"internal"`
}

type databaseStats struct {
	Dialect     string            `json:"dialect"`
	Databases   []databaseStatsDB `json:"databases"`
	TotalTables int64             `json:"total_tables"`
	TotalRows   int64             `json:"total_rows"`
}

// handleDatabaseStats mirrors GET /database/stats across every open
// database file.
//
//	@Summary		Database statistics
//	@Description	Minimum role: viewer. File sizes (main/WAL/SHM), table row counts, and SQLite internals for EVERY open database file — this agent splits storage by write-contention domain instead of one file.
//	@Tags			Database Management
//	@Produce		json
//	@Success		200	{object}	databaseStats	"Database statistics"
//	@Failure		500	{object}	wrappedError	"Failed to retrieve database statistics"
//	@Router			/database/stats [get]
func (s *Server) handleDatabaseStats(w http.ResponseWriter, r *http.Request) {
	databases := make([]databaseStatsDB, 0, len(s.dbs))
	var totalRows, totalTables int64

	for _, handle := range s.dbs {
		tables := make([]databaseTableStat, 0, len(handle.Tables))
		var rows int64
		for _, table := range handle.Tables {
			query, known := tableCountQueries[table]
			if !known {
				continue
			}
			var n int64
			if err := handle.DB.QueryRowContext(r.Context(), query).Scan(&n); err != nil {
				errorResponse(w, http.StatusInternalServerError,
					"Failed to retrieve database statistics", err.Error())
				return
			}
			tables = append(tables, databaseTableStat{Name: table, RowCount: n})
			rows += n
		}

		var internal databaseInternalStats
		var pageSize, pageCount, freelist int64
		if err := handle.DB.QueryRowContext(r.Context(), "PRAGMA page_size").Scan(&pageSize); err == nil {
			internal.PageSize = &pageSize
		}
		if err := handle.DB.QueryRowContext(r.Context(), "PRAGMA page_count").Scan(&pageCount); err == nil {
			internal.PageCount = &pageCount
		}
		if err := handle.DB.QueryRowContext(r.Context(), "PRAGMA freelist_count").Scan(&freelist); err == nil {
			freelistBytes := freelist * pageSize
			internal.FreelistCount = &freelist
			internal.FreelistBytes = &freelistBytes
		}

		databases = append(databases, databaseStatsDB{
			Name:        handle.Name,
			StoragePath: handle.Path,
			Files:       databaseFiles(handle.Path),
			Tables:      tables,
			TotalTables: len(tables),
			TotalRows:   rows,
			Internal:    internal,
		})
		totalRows += rows
		totalTables += int64(len(tables))
	}

	writeJSON(w, databaseStats{
		Dialect:     "sqlite",
		Databases:   databases,
		TotalTables: totalTables,
		TotalRows:   totalRows,
	})
}

type databaseVacuumResult struct {
	Name           string `json:"name"`
	SizeBefore     int64  `json:"size_before"`
	SizeAfter      int64  `json:"size_after"`
	SpaceReclaimed int64  `json:"space_reclaimed"`
}

type databaseVacuumResponse struct {
	Success        bool                   `json:"success"`
	Message        string                 `json:"message"`
	Timestamp      string                 `json:"timestamp"`
	Databases      []databaseVacuumResult `json:"databases"`
	SizeBefore     int64                  `json:"size_before"`
	SizeAfter      int64                  `json:"size_after"`
	SpaceReclaimed int64                  `json:"space_reclaimed"`
}

// handleDatabaseVacuum mirrors POST /database/vacuum across every open
// database file.
//
//	@Summary		Run VACUUM
//	@Description	Minimum role: admin. Rebuilds every open database file to reclaim space; temporarily doubles disk usage per file.
//	@Tags			Database Management
//	@Produce		json
//	@Success		200	{object}	databaseVacuumResponse	"VACUUM completed"
//	@Failure		500	{object}	wrappedError	"VACUUM failed"
//	@Router			/database/vacuum [post]
func (s *Server) handleDatabaseVacuum(w http.ResponseWriter, r *http.Request) {
	results := make([]databaseVacuumResult, 0, len(s.dbs))
	var before, after int64
	for _, handle := range s.dbs {
		sizeBefore := fileSize(handle.Path)
		if _, err := handle.DB.ExecContext(r.Context(), "VACUUM"); err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to run VACUUM",
				handle.Name+": "+err.Error())
			return
		}
		sizeAfter := fileSize(handle.Path)
		results = append(results, databaseVacuumResult{
			Name:           handle.Name,
			SizeBefore:     sizeBefore,
			SizeAfter:      sizeAfter,
			SpaceReclaimed: sizeBefore - sizeAfter,
		})
		before += sizeBefore
		after += sizeAfter
	}
	slog.Info("database vacuum completed", "by", auth.FromContext(r.Context()).Name,
		"space_reclaimed", before-after)

	writeJSON(w, databaseVacuumResponse{
		Success:        true,
		Message:        "VACUUM completed successfully",
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Databases:      results,
		SizeBefore:     before,
		SizeAfter:      after,
		SpaceReclaimed: before - after,
	})
}

// handleDatabaseAnalyze mirrors POST /database/analyze across every open
// database file.
//
//	@Summary		Run ANALYZE
//	@Description	Minimum role: admin. Refreshes query-planner statistics on every open database file; lightweight and safe anytime.
//	@Tags			Database Management
//	@Produce		json
//	@Success		200	"ANALYZE completed"
//	@Failure		500	{object}	wrappedError	"ANALYZE failed"
//	@Router			/database/analyze [post]
func (s *Server) handleDatabaseAnalyze(w http.ResponseWriter, r *http.Request) {
	for _, handle := range s.dbs {
		if _, err := handle.DB.ExecContext(r.Context(), "ANALYZE"); err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to run ANALYZE",
				handle.Name+": "+err.Error())
			return
		}
	}
	successResponse(w, "ANALYZE completed successfully", map[string]any{
		"databases": len(s.dbs),
	})
}

type databaseCleanupStatus struct {
	DeletedTasks int64 `json:"deleted_tasks"`
	// Days finished tasks are retained (tasks.retention_days)
	RetentionDays     int  `json:"retention_days"`
	MonitoringStorage bool `json:"monitoring_storage"`
	// Days of stored telemetry retained (monitoring.retention_days)
	MonitoringRetentionDays int `json:"monitoring_retention_days"`
}

type databaseCleanupResponse struct {
	Success       bool                  `json:"success"`
	Message       string                `json:"message"`
	Timestamp     string                `json:"timestamp"`
	CleanupStatus databaseCleanupStatus `json:"cleanup_status"`
}

// handleDatabaseCleanup mirrors POST /database/cleanup: the same retention
// pass the periodic cleanup runs — finished tasks past tasks.retention_days,
// plus stored telemetry past monitoring.retention_days.
//
//	@Summary		Trigger manual cleanup
//	@Description	Minimum role: admin. The same retention pass the periodic cleanup runs: finished tasks past tasks.retention_days plus stored telemetry past monitoring.retention_days.
//	@Tags			Database Management
//	@Produce		json
//	@Success		200	{object}	databaseCleanupResponse	"Cleanup triggered"
//	@Failure		500	{object}	wrappedError	"Cleanup failed"
//	@Router			/database/cleanup [post]
func (s *Server) handleDatabaseCleanup(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.tasks.CleanupNow(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to trigger cleanup", err.Error())
		return
	}
	s.monitor.CleanupOld(r.Context())
	slog.Info("manual database cleanup", "deleted_tasks", deleted,
		"by", auth.FromContext(r.Context()).Name)

	writeJSON(w, databaseCleanupResponse{
		Success:   true,
		Message:   "Cleanup triggered successfully",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		CleanupStatus: databaseCleanupStatus{
			DeletedTasks:            deleted,
			RetentionDays:           s.cfg.Tasks.RetentionDays,
			MonitoringStorage:       s.monitor.StorageEnabled(),
			MonitoringRetentionDays: s.cfg.Monitoring.RetentionDays,
		},
	})
}
