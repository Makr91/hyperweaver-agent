package server

import (
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

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
func databaseFiles(path string) map[string]int64 {
	main := fileSize(path)
	wal := fileSize(path + "-wal")
	shm := fileSize(path + "-shm")
	return map[string]int64{
		"database": main,
		"wal":      wal,
		"shm":      shm,
		"total":    main + wal + shm,
	}
}

// handleDatabaseStats mirrors GET /database/stats across every open
// database file.
func (s *Server) handleDatabaseStats(w http.ResponseWriter, r *http.Request) {
	databases := make([]map[string]any, 0, len(s.dbs))
	var totalRows, totalTables int64

	for _, handle := range s.dbs {
		tables := make([]map[string]any, 0, len(handle.Tables))
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
			tables = append(tables, map[string]any{"name": table, "row_count": n})
			rows += n
		}

		internal := map[string]any{}
		var pageSize, pageCount, freelist int64
		if err := handle.DB.QueryRowContext(r.Context(), "PRAGMA page_size").Scan(&pageSize); err == nil {
			internal["page_size"] = pageSize
		}
		if err := handle.DB.QueryRowContext(r.Context(), "PRAGMA page_count").Scan(&pageCount); err == nil {
			internal["page_count"] = pageCount
		}
		if err := handle.DB.QueryRowContext(r.Context(), "PRAGMA freelist_count").Scan(&freelist); err == nil {
			internal["freelist_count"] = freelist
			internal["freelist_bytes"] = freelist * pageSize
		}

		databases = append(databases, map[string]any{
			"name":         handle.Name,
			"storage_path": handle.Path,
			"files":        databaseFiles(handle.Path),
			"tables":       tables,
			"total_tables": len(tables),
			"total_rows":   rows,
			"internal":     internal,
		})
		totalRows += rows
		totalTables += int64(len(tables))
	}

	writeJSON(w, map[string]any{
		"dialect":      "sqlite",
		"databases":    databases,
		"total_tables": totalTables,
		"total_rows":   totalRows,
	})
}

// handleDatabaseVacuum mirrors POST /database/vacuum across every open
// database file.
func (s *Server) handleDatabaseVacuum(w http.ResponseWriter, r *http.Request) {
	results := make([]map[string]any, 0, len(s.dbs))
	var before, after int64
	for _, handle := range s.dbs {
		sizeBefore := fileSize(handle.Path)
		if _, err := handle.DB.ExecContext(r.Context(), "VACUUM"); err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to run VACUUM",
				handle.Name+": "+err.Error())
			return
		}
		sizeAfter := fileSize(handle.Path)
		results = append(results, map[string]any{
			"name":            handle.Name,
			"size_before":     sizeBefore,
			"size_after":      sizeAfter,
			"space_reclaimed": sizeBefore - sizeAfter,
		})
		before += sizeBefore
		after += sizeAfter
	}
	slog.Info("database vacuum completed", "by", auth.FromContext(r.Context()).Name,
		"space_reclaimed", before-after)

	successResponse(w, "VACUUM completed successfully", map[string]any{
		"databases":       results,
		"size_before":     before,
		"size_after":      after,
		"space_reclaimed": before - after,
	})
}

// handleDatabaseAnalyze mirrors POST /database/analyze across every open
// database file.
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

// handleDatabaseCleanup mirrors POST /database/cleanup: the same retention
// pass the periodic cleanup runs — finished tasks past tasks.retention_days,
// plus stored telemetry past monitoring.retention_days.
func (s *Server) handleDatabaseCleanup(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.tasks.CleanupNow(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to trigger cleanup", err.Error())
		return
	}
	s.monitor.CleanupOld(r.Context())
	slog.Info("manual database cleanup", "deleted_tasks", deleted,
		"by", auth.FromContext(r.Context()).Name)

	successResponse(w, "Cleanup triggered successfully", map[string]any{
		"cleanup_status": map[string]any{
			"deleted_tasks":       deleted,
			"retention_days":      s.cfg.Tasks.RetentionDays,
			"monitoring_storage":  s.monitor.StorageEnabled(),
			"monitoring_retained": strconv.Itoa(s.cfg.Monitoring.RetentionDays) + " days",
		},
	})
}
