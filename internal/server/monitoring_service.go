package server

import (
	"net/http"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// monitoringHostResponse is GET /monitoring/host's answer.
type monitoringHostResponse struct {
	Host           string `json:"host"`
	Hostname       string `json:"hostname"`
	Platform       string `json:"platform"`
	Release        string `json:"release"`
	Arch           string `json:"arch"`
	Uptime         uint64 `json:"uptime"`
	OS             string `json:"os"`
	CPUs           int    `json:"cpus"`
	MemoryBytes    uint64 `json:"memory_bytes"`
	StorageEnabled bool   `json:"storage_enabled"`
	// The last successful collection; null when none (or realtime-only mode)
	LastCollection *string `json:"last_collection"`
}

// @Summary		Host information and monitoring state
// @Description	Minimum role: viewer.
// @Tags			Host Monitoring
// @Produce		json
// @Success		200	{object}	monitoringHostResponse	"Host information"
// @Router			/monitoring/host [get]
func (s *Server) handleMonitoringHost(w http.ResponseWriter, _ *http.Request) {
	info := hostinfo.Get()
	response := monitoringHostResponse{
		Host:           s.monitor.Sampler().Hostname(),
		Hostname:       s.monitor.Sampler().Hostname(),
		Platform:       nodePlatform(),
		Release:        hostinfo.KernelRelease(),
		Arch:           info.Arch,
		Uptime:         hostinfo.UptimeSeconds(),
		OS:             info.OS,
		CPUs:           info.CPUs,
		MemoryBytes:    info.MemoryBytes,
		StorageEnabled: s.monitor.StorageEnabled(),
	}
	if last := s.monitor.LastCollection(); !last.IsZero() {
		formatted := last.UTC().Format(time.RFC3339)
		response.LastCollection = &formatted
	}
	writeJSON(w, response)
}

// monitoringSummaryFlags is the summary's mode block.
type monitoringSummaryFlags struct {
	StorageEnabled bool `json:"storage_enabled"`
	Collector      bool `json:"collector"`
}

// monitoringSummaryResponse is GET /monitoring/summary's answer.
type monitoringSummaryResponse struct {
	Host    string                 `json:"host"`
	Summary monitoringSummaryFlags `json:"summary"`
	// Per-table row counts (empty in realtime mode — nothing is stored)
	RecordCounts map[string]int64 `json:"recordCounts"`
	// Per-table latest sample times, RFC 3339
	LatestData map[string]string `json:"latestData"`
	// The last collection time; null when none
	LastCollected *string `json:"lastCollected"`
	// Milliseconds spent serving the request
	QueryTime int64 `json:"queryTime"`
}

// @Summary		Monitoring summary
// @Description	Minimum role: viewer. Record counts and latest sample times per telemetry table (empty in realtime mode — nothing is stored).
// @Tags			Host Monitoring
// @Produce		json
// @Success		200	{object}	monitoringSummaryResponse	"Monitoring summary"
// @Failure		500	{object}	wrappedError				"Failed to get monitoring summary"
// @Router			/monitoring/summary [get]
func (s *Server) handleMonitoringSummary(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	response := monitoringSummaryResponse{
		Host: s.monitor.Sampler().Hostname(),
		Summary: monitoringSummaryFlags{
			StorageEnabled: s.monitor.StorageEnabled(),
			Collector:      s.monitor.Running(),
		},
		RecordCounts: map[string]int64{},
		LatestData:   map[string]string{},
	}

	if s.monitor.StorageEnabled() {
		counts, latest, err := s.monitor.Store().Counts(r.Context())
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get monitoring summary", err.Error())
			return
		}
		response.RecordCounts = counts
		for table, at := range latest {
			if at != nil {
				response.LatestData[table] = at.UTC().Format(time.RFC3339)
			}
		}
	}
	if last := s.monitor.LastCollection(); !last.IsZero() {
		formatted := last.UTC().Format(time.RFC3339)
		response.LastCollected = &formatted
	}
	response.QueryTime = queryTimeSince(start)
	writeJSON(w, response)
}

// monitoringStatusResponse is GET /monitoring/status's answer. config and
// stats are the service's own free-form documents.
type monitoringStatusResponse struct {
	IsRunning     bool           `json:"isRunning"`
	IsInitialized bool           `json:"isInitialized"`
	Config        map[string]any `json:"config"`
	Stats         map[string]any `json:"stats"`
	Note          string         `json:"note"`
}

// @Summary		Monitoring service status
// @Description	Minimum role: viewer.
// @Tags			Host Monitoring
// @Produce		json
// @Success		200	{object}	monitoringStatusResponse	"Service status"
// @Router			/monitoring/status [get]
func (s *Server) handleMonitoringStatus(w http.ResponseWriter, _ *http.Request) {
	note := "Realtime mode: every request samples the OS live; enable monitoring.storage_enabled for stored history."
	if s.monitor.StorageEnabled() {
		note = "Storage mode: a background collector writes time series into per-datatype database files."
	}
	writeJSON(w, monitoringStatusResponse{
		IsRunning:     s.monitor.Running() || !s.monitor.StorageEnabled(),
		IsInitialized: true,
		Config: map[string]any{
			"storage_enabled":     s.cfg.Monitoring.StorageEnabled,
			"collection_interval": s.cfg.Monitoring.CollectionInterval,
			"retention_days":      s.cfg.Monitoring.RetentionDays,
		},
		Stats: s.monitor.Stats(),
		Note:  note,
	})
}

// monitoringHealthService is the health answer's service block.
type monitoringHealthService struct {
	StorageEnabled bool           `json:"storage_enabled"`
	Collector      bool           `json:"collector"`
	Stats          map[string]any `json:"stats"`
}

// monitoringHealthResponse is GET /monitoring/health's answer.
type monitoringHealthResponse struct {
	// healthy | degraded (collector errors) | stopped (storage on, collector down)
	Status  string                  `json:"status"`
	Uptime  uint64                  `json:"uptime"`
	Version string                  `json:"version"`
	Service monitoringHealthService `json:"service"`
	// The last collection time; null when none
	LastUpdate *string `json:"lastUpdate"`
}

// @Summary		Monitoring health check
// @Description	Minimum role: viewer. healthy | degraded (collector errors) | stopped (storage on, collector down). No fault-management rollup — fmadm is illumos-only.
// @Tags			Host Monitoring
// @Produce		json
// @Success		200	{object}	monitoringHealthResponse	"Health information"
// @Router			/monitoring/health [get]
func (s *Server) handleMonitoringHealth(w http.ResponseWriter, _ *http.Request) {
	status := "healthy"
	if s.monitor.StorageEnabled() && !s.monitor.Running() {
		status = "stopped"
	}
	stats := s.monitor.Stats()
	if _, hadError := stats["last_error"]; hadError && status == "healthy" {
		status = "degraded"
	}

	response := monitoringHealthResponse{
		Status:  status,
		Uptime:  hostinfo.UptimeSeconds(),
		Version: version.Version,
		Service: monitoringHealthService{
			StorageEnabled: s.monitor.StorageEnabled(),
			Collector:      s.monitor.Running(),
			Stats:          stats,
		},
	}
	if last := s.monitor.LastCollection(); !last.IsZero() {
		formatted := last.UTC().Format(time.RFC3339)
		response.LastUpdate = &formatted
	}
	writeJSON(w, response)
}
