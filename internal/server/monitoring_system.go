package server

import (
	"net/http"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
)

// stripCores removes per-core data unless include_cores=true (the Node
// agent's include_cores contract: per_core_parsed appears only on request).
func stripCores(samples []monitoring.CPUSample, includeCores bool) []monitoring.CPUSample {
	if includeCores {
		return samples
	}
	out := make([]monitoring.CPUSample, len(samples))
	copy(out, samples)
	for i := range out {
		out[i].PerCoreParsed = nil
	}
	return out
}

// cpuSamples answers the mode split: stored history when storage is enabled,
// the single live sample otherwise.
func (s *Server) cpuSamples(r *http.Request, q monitoringQuery) ([]monitoring.CPUSample, string, error) {
	if s.monitor.StorageEnabled() {
		samples, err := s.monitor.Store().CPUHistory(r.Context(),
			&monitoring.HistoryFilter{Since: q.since, Limit: q.limit})
		return samples, "stored", err
	}
	sample, err := s.monitor.Sampler().SampleCPU(r.Context())
	if err != nil {
		return nil, "realtime", err
	}
	return []monitoring.CPUSample{*sample}, "realtime", nil
}

// cpuStatsResponse is GET /monitoring/system/cpu's answer.
type cpuStatsResponse struct {
	CPU           []monitoring.CPUSample `json:"cpu"`
	TotalCount    int                    `json:"totalCount"`
	ReturnedCount int                    `json:"returnedCount"`
	Sampling      monitoringSamplingMeta `json:"sampling"`
	// Milliseconds spent serving the request
	QueryTime int64 `json:"queryTime"`
	// The newest sample; null when none
	Latest *monitoring.CPUSample `json:"latest"`
}

// @Summary		CPU statistics
// @Description	Minimum role: viewer. Realtime mode (storage disabled, the default): one live sample; since is effectively ignored. Storage mode: stored samples, newest first.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit			query	int		false	"Maximum samples"	default(100)
// @Param			since			query	string	false	"Stored samples at or after this time (storage mode)"
// @Param			include_cores	query	bool	false	"Include the per_core_parsed array on every sample"	default(false)
// @Success		200	{object}	cpuStatsResponse	"CPU statistics"
// @Failure		500	{object}	wrappedError		"Failed to get CPU statistics"
// @Router			/monitoring/system/cpu [get]
func (s *Server) handleMonitoringCPU(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := parseMonitoringQuery(r)
	includeCores := r.URL.Query().Get("include_cores") == "true"

	samples, strategy, err := s.cpuSamples(r, q)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get CPU statistics", err.Error())
		return
	}
	samples = stripCores(samples, includeCores)

	response := cpuStatsResponse{
		CPU:           samples,
		TotalCount:    len(samples),
		ReturnedCount: len(samples),
		Sampling:      samplingMeta(strategy, len(samples)),
		QueryTime:     queryTimeSince(start),
	}
	if len(samples) > 0 {
		response.Latest = &samples[0]
	}
	writeJSON(w, response)
}

// memoryStatsResponse is GET /monitoring/system/memory's answer.
type memoryStatsResponse struct {
	Memory        []monitoring.MemorySample `json:"memory"`
	TotalCount    int                       `json:"totalCount"`
	ReturnedCount int                       `json:"returnedCount"`
	Sampling      monitoringSamplingMeta    `json:"sampling"`
	// Milliseconds spent serving the request
	QueryTime int64 `json:"queryTime"`
	// The newest sample; null when none
	Latest *monitoring.MemorySample `json:"latest"`
}

// @Summary		Memory statistics
// @Description	Minimum role: viewer. Realtime mode: one live sample; storage mode: stored samples, newest first.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit	query	int		false	"Maximum samples"	default(100)
// @Param			since	query	string	false	"Stored samples at or after this time (storage mode)"
// @Success		200	{object}	memoryStatsResponse	"Memory statistics"
// @Failure		500	{object}	wrappedError		"Failed to get memory statistics"
// @Router			/monitoring/system/memory [get]
func (s *Server) handleMonitoringMemory(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := parseMonitoringQuery(r)

	var samples []monitoring.MemorySample
	var strategy string
	if s.monitor.StorageEnabled() {
		stored, err := s.monitor.Store().MemoryHistory(r.Context(),
			&monitoring.HistoryFilter{Since: q.since, Limit: q.limit})
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get memory statistics", err.Error())
			return
		}
		samples, strategy = stored, "stored"
	} else {
		sample, err := s.monitor.Sampler().SampleMemory(r.Context())
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get memory statistics", err.Error())
			return
		}
		samples, strategy = []monitoring.MemorySample{*sample}, "realtime"
	}

	response := memoryStatsResponse{
		Memory:        samples,
		TotalCount:    len(samples),
		ReturnedCount: len(samples),
		Sampling:      samplingMeta(strategy, len(samples)),
		QueryTime:     queryTimeSince(start),
	}
	if len(samples) > 0 {
		response.Latest = &samples[0]
	}
	writeJSON(w, response)
}

// loadAveragesBlock is the 1/5/15-minute load-average trio (zeros on
// Windows — the platform has no concept).
type loadAveragesBlock struct {
	OneMin     float64 `json:"one_min"`
	FiveMin    float64 `json:"five_min"`
	FifteenMin float64 `json:"fifteen_min"`
}

// processActivityBlock carries the run-queue counts where the platform
// reports them (Linux); zeros elsewhere.
type processActivityBlock struct {
	Running int `json:"running"`
	Blocked int `json:"blocked"`
}

// loadMetricsEntry is one load-metrics chart item.
type loadMetricsEntry struct {
	Timestamp       time.Time            `json:"timestamp"`
	LoadAverages    loadAveragesBlock    `json:"load_averages"`
	ProcessActivity processActivityBlock `json:"process_activity"`
	CPUCount        int                  `json:"cpu_count"`
}

// loadMetricsMetadata describes the load listing.
type loadMetricsMetadata struct {
	Description     string   `json:"description"`
	MetricsIncluded []string `json:"metrics_included"`
}

// loadMetricsResponse is GET /monitoring/system/load's answer.
type loadMetricsResponse struct {
	Load       []loadMetricsEntry  `json:"load"`
	TotalCount int                 `json:"totalCount"`
	Metadata   loadMetricsMetadata `json:"metadata"`
	// The newest entry; null when none
	Latest *loadMetricsEntry `json:"latest"`
}

// loadEntry reshapes a CPU sample into the load-metrics chart shape (the
// Node agent's /monitoring/system/load items). Activity counters the
// platform does not report stay zero.
func loadEntry(sample *monitoring.CPUSample) loadMetricsEntry {
	return loadMetricsEntry{
		Timestamp: sample.ScanTimestamp,
		LoadAverages: loadAveragesBlock{
			OneMin:     sample.LoadAvg1Min,
			FiveMin:    sample.LoadAvg5Min,
			FifteenMin: sample.LoadAvg15Min,
		},
		ProcessActivity: processActivityBlock{
			Running: sample.ProcessesRunning,
			Blocked: sample.ProcessesBlocked,
		},
		CPUCount: sample.CPUCount,
	}
}

// @Summary		System load metrics
// @Description	Minimum role: viewer. Load averages and process activity reshaped for charting. Load averages are zeros on Windows; run-queue counts are Linux-only — absent counters stay zero, honestly.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit	query	int		false	"Maximum entries"	default(100)
// @Param			since	query	string	false	"Stored samples at or after this time (storage mode)"
// @Success		200	{object}	loadMetricsResponse	"Load metrics"
// @Failure		500	{object}	wrappedError		"Failed to get system load metrics"
// @Router			/monitoring/system/load [get]
func (s *Server) handleMonitoringLoad(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)

	samples, _, err := s.cpuSamples(r, q)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get system load metrics", err.Error())
		return
	}

	entries := make([]loadMetricsEntry, 0, len(samples))
	for i := range samples {
		entries = append(entries, loadEntry(&samples[i]))
	}
	response := loadMetricsResponse{
		Load:       entries,
		TotalCount: len(entries),
		Metadata: loadMetricsMetadata{
			Description: "Load averages and process activity (load averages are zeros on Windows — the platform has no concept)",
			MetricsIncluded: []string{
				"load_averages", "process_activity", "cpu_count",
			},
		},
	}
	if len(entries) > 0 {
		response.Latest = &entries[0]
	}
	writeJSON(w, response)
}
