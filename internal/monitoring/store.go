package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Per-datatype schemas, applied by db.Open via user_version tracking — one
// database file per family (monitoring-cpu.sqlite, monitoring-memory.sqlite,
// monitoring-network.sqlite) so telemetry write churn never contends across
// families or with the main databases. Timestamps are fixed-width UTC text
// (the tasks/machines convention) so lexicographic order is chronological.

// CPUMigrations is the monitoring-cpu.sqlite schema.
var CPUMigrations = []string{
	`CREATE TABLE cpu_samples (
		id                  INTEGER PRIMARY KEY AUTOINCREMENT,
		host                TEXT NOT NULL,
		cpu_count           INTEGER NOT NULL,
		cpu_utilization_pct REAL NOT NULL,
		user_pct            REAL NOT NULL,
		system_pct          REAL NOT NULL,
		idle_pct            REAL NOT NULL,
		load_avg_1min       REAL NOT NULL DEFAULT 0,
		load_avg_5min       REAL NOT NULL DEFAULT 0,
		load_avg_15min      REAL NOT NULL DEFAULT 0,
		processes_running   INTEGER NOT NULL DEFAULT 0,
		processes_blocked   INTEGER NOT NULL DEFAULT 0,
		per_core_data       TEXT,
		scan_timestamp      TEXT NOT NULL
	);
	CREATE INDEX idx_cpu_samples_scan ON cpu_samples (scan_timestamp DESC);`,
	`ALTER TABLE cpu_samples ADD COLUMN io_delay_pct REAL;`,
}

// MemoryMigrations is the monitoring-memory.sqlite schema.
var MemoryMigrations = []string{
	`CREATE TABLE memory_samples (
		id                     INTEGER PRIMARY KEY AUTOINCREMENT,
		host                   TEXT NOT NULL,
		total_memory_bytes     INTEGER NOT NULL,
		available_memory_bytes INTEGER NOT NULL,
		used_memory_bytes      INTEGER NOT NULL,
		free_memory_bytes      INTEGER NOT NULL,
		memory_utilization_pct REAL NOT NULL,
		swap_total_bytes       INTEGER NOT NULL DEFAULT 0,
		swap_used_bytes        INTEGER NOT NULL DEFAULT 0,
		swap_free_bytes        INTEGER NOT NULL DEFAULT 0,
		swap_utilization_pct   REAL NOT NULL DEFAULT 0,
		scan_timestamp         TEXT NOT NULL
	);
	CREATE INDEX idx_memory_samples_scan ON memory_samples (scan_timestamp DESC);`,
}

// NetworkMigrations is the monitoring-network.sqlite schema.
var NetworkMigrations = []string{
	`CREATE TABLE network_samples (
		id                 INTEGER PRIMARY KEY AUTOINCREMENT,
		host               TEXT NOT NULL,
		link               TEXT NOT NULL,
		ipackets           INTEGER NOT NULL,
		rbytes             INTEGER NOT NULL,
		ierrors            INTEGER NOT NULL,
		opackets           INTEGER NOT NULL,
		obytes             INTEGER NOT NULL,
		oerrors            INTEGER NOT NULL,
		rx_bps             INTEGER NOT NULL DEFAULT 0,
		tx_bps             INTEGER NOT NULL DEFAULT 0,
		rx_mbps            REAL NOT NULL DEFAULT 0,
		tx_mbps            REAL NOT NULL DEFAULT 0,
		time_delta_seconds REAL NOT NULL DEFAULT 0,
		scan_timestamp     TEXT NOT NULL
	);
	CREATE INDEX idx_network_samples_scan ON network_samples (scan_timestamp DESC);
	CREATE INDEX idx_network_samples_link ON network_samples (link);`,
}

const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// Store persists telemetry samples across the three per-datatype databases.
// A nil Store (storage disabled) is valid: queries answer empty, inserts are
// never called.
type Store struct {
	cpuDB     *sql.DB
	memoryDB  *sql.DB
	networkDB *sql.DB
}

// NewStore wraps the opened telemetry databases.
func NewStore(cpuDB, memoryDB, networkDB *sql.DB) *Store {
	return &Store{cpuDB: cpuDB, memoryDB: memoryDB, networkDB: networkDB}
}

// InsertCPU records one CPU sample.
func (s *Store) InsertCPU(ctx context.Context, sample *CPUSample) error {
	var perCore any
	if raw := marshalCores(sample.PerCoreParsed); raw != nil {
		perCore = string(raw)
	}
	_, err := s.cpuDB.ExecContext(ctx, `INSERT INTO cpu_samples
		(host, cpu_count, cpu_utilization_pct, user_pct, system_pct, idle_pct,
		 load_avg_1min, load_avg_5min, load_avg_15min,
		 processes_running, processes_blocked, per_core_data, io_delay_pct,
		 scan_timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sample.Host, sample.CPUCount, sample.CPUUtilizationPct, sample.UserPct,
		sample.SystemPct, sample.IdlePct, sample.LoadAvg1Min, sample.LoadAvg5Min,
		sample.LoadAvg15Min, sample.ProcessesRunning, sample.ProcessesBlocked,
		perCore, sample.IODelayPct, formatTime(sample.ScanTimestamp))
	return err
}

// InsertMemory records one memory sample.
func (s *Store) InsertMemory(ctx context.Context, sample *MemorySample) error {
	_, err := s.memoryDB.ExecContext(ctx, `INSERT INTO memory_samples
		(host, total_memory_bytes, available_memory_bytes, used_memory_bytes,
		 free_memory_bytes, memory_utilization_pct, swap_total_bytes,
		 swap_used_bytes, swap_free_bytes, swap_utilization_pct, scan_timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sample.Host, sample.TotalMemoryBytes, sample.AvailableMemoryBytes,
		sample.UsedMemoryBytes, sample.FreeMemoryBytes, sample.MemoryUtilizationPct,
		sample.SwapTotalBytes, sample.SwapUsedBytes, sample.SwapFreeBytes,
		sample.SwapUtilizationPct, formatTime(sample.ScanTimestamp))
	return err
}

// InsertNetwork records one collector tick's interface samples.
func (s *Store) InsertNetwork(ctx context.Context, samples []NetworkSample) error {
	for i := range samples {
		sample := &samples[i]
		_, err := s.networkDB.ExecContext(ctx, `INSERT INTO network_samples
			(host, link, ipackets, rbytes, ierrors, opackets, obytes, oerrors,
			 rx_bps, tx_bps, rx_mbps, tx_mbps, time_delta_seconds, scan_timestamp)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sample.Host, sample.Link, sample.IPackets, sample.RBytes,
			sample.IErrors, sample.OPackets, sample.OBytes, sample.OErrors,
			sample.RxBps, sample.TxBps, sample.RxMbps, sample.TxMbps,
			sample.TimeDeltaSeconds, formatTime(sample.ScanTimestamp))
		if err != nil {
			return err
		}
	}
	return nil
}

// HistoryFilter selects stored samples.
type HistoryFilter struct {
	Since *time.Time
	Link  string // network only
	Limit int
}

func (f *HistoryFilter) limit() int {
	if f.Limit <= 0 {
		return 100
	}
	return f.Limit
}

// CPUHistory returns stored CPU samples, newest first.
func (s *Store) CPUHistory(ctx context.Context, f *HistoryFilter) ([]CPUSample, error) {
	var query strings.Builder
	query.WriteString(`SELECT host, cpu_count, cpu_utilization_pct, user_pct,
		system_pct, idle_pct, load_avg_1min, load_avg_5min, load_avg_15min,
		processes_running, processes_blocked, per_core_data, io_delay_pct,
		scan_timestamp FROM cpu_samples`)
	args := []any{}
	if f.Since != nil {
		query.WriteString(" WHERE scan_timestamp >= ?")
		args = append(args, formatTime(*f.Since))
	}
	query.WriteString(" ORDER BY scan_timestamp DESC LIMIT ?")
	args = append(args, f.limit())

	rows, err := s.cpuDB.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	samples := []CPUSample{}
	for rows.Next() {
		var sample CPUSample
		var perCore sql.NullString
		var ioDelay sql.NullFloat64
		var scanned string
		if serr := rows.Scan(&sample.Host, &sample.CPUCount, &sample.CPUUtilizationPct,
			&sample.UserPct, &sample.SystemPct, &sample.IdlePct,
			&sample.LoadAvg1Min, &sample.LoadAvg5Min, &sample.LoadAvg15Min,
			&sample.ProcessesRunning, &sample.ProcessesBlocked, &perCore, &ioDelay,
			&scanned); serr != nil {
			return nil, serr
		}
		if parsed, perr := time.Parse(timeLayout, scanned); perr == nil {
			sample.ScanTimestamp = parsed
		}
		if perCore.Valid {
			if uerr := json.Unmarshal([]byte(perCore.String), &sample.PerCoreParsed); uerr != nil {
				sample.PerCoreParsed = nil
			}
		}
		if ioDelay.Valid {
			value := ioDelay.Float64
			sample.IODelayPct = &value
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

// MemoryHistory returns stored memory samples, newest first.
func (s *Store) MemoryHistory(ctx context.Context, f *HistoryFilter) ([]MemorySample, error) {
	var query strings.Builder
	query.WriteString(`SELECT host, total_memory_bytes, available_memory_bytes,
		used_memory_bytes, free_memory_bytes, memory_utilization_pct,
		swap_total_bytes, swap_used_bytes, swap_free_bytes, swap_utilization_pct,
		scan_timestamp FROM memory_samples`)
	args := []any{}
	if f.Since != nil {
		query.WriteString(" WHERE scan_timestamp >= ?")
		args = append(args, formatTime(*f.Since))
	}
	query.WriteString(" ORDER BY scan_timestamp DESC LIMIT ?")
	args = append(args, f.limit())

	rows, err := s.memoryDB.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	samples := []MemorySample{}
	for rows.Next() {
		var sample MemorySample
		var scanned string
		if serr := rows.Scan(&sample.Host, &sample.TotalMemoryBytes,
			&sample.AvailableMemoryBytes, &sample.UsedMemoryBytes,
			&sample.FreeMemoryBytes, &sample.MemoryUtilizationPct,
			&sample.SwapTotalBytes, &sample.SwapUsedBytes, &sample.SwapFreeBytes,
			&sample.SwapUtilizationPct, &scanned); serr != nil {
			return nil, serr
		}
		if parsed, perr := time.Parse(timeLayout, scanned); perr == nil {
			sample.ScanTimestamp = parsed
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

// NetworkHistory returns stored network samples, newest first.
func (s *Store) NetworkHistory(ctx context.Context, f *HistoryFilter) ([]NetworkSample, error) {
	var query strings.Builder
	query.WriteString(`SELECT host, link, ipackets, rbytes, ierrors, opackets,
		obytes, oerrors, rx_bps, tx_bps, rx_mbps, tx_mbps, time_delta_seconds,
		scan_timestamp FROM network_samples`)
	clauses := []string{}
	args := []any{}
	if f.Since != nil {
		clauses = append(clauses, "scan_timestamp >= ?")
		args = append(args, formatTime(*f.Since))
	}
	if f.Link != "" {
		clauses = append(clauses, "link = ?")
		args = append(args, f.Link)
	}
	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	query.WriteString(" ORDER BY scan_timestamp DESC LIMIT ?")
	args = append(args, f.limit())

	rows, err := s.networkDB.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	samples := []NetworkSample{}
	for rows.Next() {
		var sample NetworkSample
		var scanned string
		if serr := rows.Scan(&sample.Host, &sample.Link, &sample.IPackets,
			&sample.RBytes, &sample.IErrors, &sample.OPackets, &sample.OBytes,
			&sample.OErrors, &sample.RxBps, &sample.TxBps, &sample.RxMbps,
			&sample.TxMbps, &sample.TimeDeltaSeconds, &scanned); serr != nil {
			return nil, serr
		}
		if parsed, perr := time.Parse(timeLayout, scanned); perr == nil {
			sample.ScanTimestamp = parsed
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

// Counts reports per-table row counts and each table's latest sample time —
// GET /monitoring/summary's recordCounts/latestData.
func (s *Store) Counts(ctx context.Context) (counts map[string]int64, latest map[string]*time.Time, err error) {
	counts = map[string]int64{}
	latest = map[string]*time.Time{}
	for _, table := range []struct {
		name string
		db   *sql.DB
	}{
		{"cpu_samples", s.cpuDB},
		{"memory_samples", s.memoryDB},
		{"network_samples", s.networkDB},
	} {
		var n int64
		var newest sql.NullString
		// Table names are compile-time literals from the slice above.
		if err := table.db.QueryRowContext(ctx,
			"SELECT COUNT(*), MAX(scan_timestamp) FROM "+table.name).Scan(&n, &newest); err != nil {
			return nil, nil, err
		}
		counts[table.name] = n
		if newest.Valid {
			if parsed, perr := time.Parse(timeLayout, newest.String); perr == nil {
				latest[table.name] = &parsed
			}
		}
	}
	return counts, latest, nil
}

// DeleteBefore removes samples older than cutoff from all three databases,
// returning the total rows removed — the retention cleanup.
func (s *Store) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	var deleted int64
	stamp := formatTime(cutoff)
	for _, target := range []struct {
		db   *sql.DB
		stmt string
	}{
		{s.cpuDB, "DELETE FROM cpu_samples WHERE scan_timestamp < ?"},
		{s.memoryDB, "DELETE FROM memory_samples WHERE scan_timestamp < ?"},
		{s.networkDB, "DELETE FROM network_samples WHERE scan_timestamp < ?"},
	} {
		res, err := target.db.ExecContext(ctx, target.stmt, stamp)
		if err != nil {
			return deleted, err
		}
		if n, aerr := res.RowsAffected(); aerr == nil {
			deleted += n
		}
	}
	return deleted, nil
}
