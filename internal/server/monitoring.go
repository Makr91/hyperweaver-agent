package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// Host telemetry endpoints (/monitoring/*, the `monitoring` capability
// token) — the Node agent's Host Monitoring group, reshaped per Mark's
// 2026-07-05 ruling: always-on REALTIME sampling; monitoring.storage_enabled
// adds stored history (per-datatype database files) behind the same
// endpoints. Illumos-only monitoring families (ZFS pools/datasets/ARC,
// zpool-iostat disk IO, netstat routes) have no analog on this host and are
// deliberately absent.

// monitoringQuery carries the common history query parameters.
type monitoringQuery struct {
	limit int
	since *time.Time
}

func parseMonitoringQuery(r *http.Request) monitoringQuery {
	q := monitoringQuery{limit: 100}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			q.limit = parsed
		}
	}
	if raw := r.URL.Query().Get("since"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			q.since = &parsed
		}
	}
	return q
}

// monitoringSamplingMeta is the time-series sampling metadata block (the
// MonitoringSampling contract): this agent never downsamples, so applied is
// always false — strategy names which mode answered (realtime = single live
// sample, stored = database rows).
type monitoringSamplingMeta struct {
	Applied         bool   `json:"applied"`
	Strategy        string `json:"strategy"`
	SamplesReturned int    `json:"samplesReturned"`
}

// samplingMeta builds the sampling metadata block.
func samplingMeta(strategy string, returned int) monitoringSamplingMeta {
	return monitoringSamplingMeta{
		Applied:         false,
		Strategy:        strategy,
		SamplesReturned: returned,
	}
}

func queryTimeSince(start time.Time) string {
	return fmt.Sprintf("%dms", time.Since(start).Milliseconds())
}

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
	QueryTime     string                 `json:"queryTime"`
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
	QueryTime     string                    `json:"queryTime"`
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
	QueryTime     string  `json:"queryTime"`
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

// monitoringCollectRequest is POST /monitoring/collect's optional body.
type monitoringCollectRequest struct {
	// network | storage | all (default all) — echoed for contract parity
	Type string `json:"type"`
}

// monitoringCollectResponse is POST /monitoring/collect's answer.
type monitoringCollectResponse struct {
	Success bool   `json:"success"`
	Type    string `json:"type"`
	// Per-family outcomes (collected | sampled | failed: ...)
	Results map[string]string `json:"results"`
}

// @Summary		Trigger immediate collection
// @Description	Minimum role: operator. One collection pass over every telemetry family this host has (cpu, memory, network); samples persist when storage is enabled. The type field is accepted for contract parity — there is no illumos storage family to exclude here.
// @Tags			Host Monitoring
// @Accept			json
// @Produce		json
// @Param			request	body		monitoringCollectRequest	false	"Collection type (contract parity)"
// @Success		200		{object}	monitoringCollectResponse	"Collection triggered"
// @Router			/monitoring/collect [post]
func (s *Server) handleMonitoringCollect(w http.ResponseWriter, r *http.Request) {
	var body monitoringCollectRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Failed to trigger collection", "Invalid JSON body")
		return
	}
	collectionType := body.Type
	if collectionType == "" {
		collectionType = "all"
	}

	// One collection pass covers every family this host has; the type is
	// echoed for contract parity (there is no illumos storage family to
	// exclude here).
	results := s.monitor.CollectOnce(r.Context())
	writeJSON(w, monitoringCollectResponse{
		Success: true,
		Type:    collectionType,
		Results: results,
	})
}

// monitoringPagination is the monitoring listings' pagination envelope.
type monitoringPagination struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

// monitoringInterfacesResponse is GET /monitoring/network/interfaces' answer.
type monitoringInterfacesResponse struct {
	Interfaces []monitoring.Interface `json:"interfaces"`
	TotalCount int                    `json:"totalCount"`
	Pagination monitoringPagination   `json:"pagination"`
}

// @Summary		Network interfaces
// @Description	Minimum role: viewer. Live configuration view (name, MTU, state, MAC, addresses). dladm-only fields (over, speed, vid, zone) have no analog and are absent.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit	query	int		false	"Maximum rows"	default(100)
// @Param			offset	query	int		false	"Page offset"	default(0)
// @Param			state	query	string	false	"Filter by state (up | down)"
// @Param			link	query	string	false	"Filter by interface name"
// @Success		200	{object}	monitoringInterfacesResponse	"Network interfaces"
// @Failure		500	{object}	wrappedError					"Failed to get network interfaces"
// @Router			/monitoring/network/interfaces [get]
func (s *Server) handleMonitoringInterfaces(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)
	interfaces, err := s.monitor.Sampler().Interfaces(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get network interfaces", err.Error())
		return
	}

	if state := r.URL.Query().Get("state"); state != "" {
		filtered := interfaces[:0]
		for _, iface := range interfaces {
			if iface.State == state {
				filtered = append(filtered, iface)
			}
		}
		interfaces = filtered
	}
	if link := r.URL.Query().Get("link"); link != "" {
		filtered := interfaces[:0]
		for _, iface := range interfaces {
			if iface.Link == link {
				filtered = append(filtered, iface)
			}
		}
		interfaces = filtered
	}

	total := len(interfaces)
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	if offset > total {
		offset = total
	}
	end := offset + q.limit
	if end > total {
		end = total
	}

	writeJSON(w, monitoringInterfacesResponse{
		Interfaces: interfaces[offset:end],
		TotalCount: total,
		Pagination: monitoringPagination{
			Limit:   q.limit,
			Offset:  offset,
			HasMore: total > end,
		},
	})
}

// networkUsageMetadata is the network-usage listing's interface roster.
type networkUsageMetadata struct {
	ActiveInterfacesCount int      `json:"activeInterfacesCount"`
	InterfaceList         []string `json:"interfaceList"`
}

// networkUsageResponse is GET /monitoring/network/usage's answer.
type networkUsageResponse struct {
	Usage         []monitoring.NetworkSample `json:"usage"`
	TotalCount    int                        `json:"totalCount"`
	ReturnedCount int                        `json:"returnedCount"`
	Sampling      monitoringSamplingMeta     `json:"sampling"`
	Metadata      networkUsageMetadata       `json:"metadata"`
	QueryTime     string                     `json:"queryTime"`
}

// @Summary		Network usage
// @Description	Minimum role: viewer. Per-interface counters with computed rates. Realtime mode: one live observation per interface; storage mode: stored samples, newest first.
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit	query	int		false	"Maximum samples"	default(100)
// @Param			since	query	string	false	"Stored samples at or after this time (storage mode)"
// @Param			link	query	string	false	"Filter by interface name"
// @Success		200	{object}	networkUsageResponse	"Network usage"
// @Failure		500	{object}	wrappedError			"Failed to get network usage"
// @Router			/monitoring/network/usage [get]
func (s *Server) handleMonitoringNetworkUsage(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	q := parseMonitoringQuery(r)
	link := r.URL.Query().Get("link")

	var samples []monitoring.NetworkSample
	var strategy string
	if s.monitor.StorageEnabled() {
		stored, err := s.monitor.Store().NetworkHistory(r.Context(),
			&monitoring.HistoryFilter{Since: q.since, Link: link, Limit: q.limit})
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get network usage", err.Error())
			return
		}
		samples, strategy = stored, "stored"
	} else {
		live, err := s.monitor.Sampler().SampleNetwork(r.Context())
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get network usage", err.Error())
			return
		}
		if link != "" {
			filtered := live[:0]
			for i := range live {
				if live[i].Link == link {
					filtered = append(filtered, live[i])
				}
			}
			live = filtered
		}
		samples, strategy = live, "realtime"
	}

	interfaceSet := map[string]bool{}
	for i := range samples {
		interfaceSet[samples[i].Link] = true
	}
	interfaceList := make([]string, 0, len(interfaceSet))
	for name := range interfaceSet {
		interfaceList = append(interfaceList, name)
	}

	writeJSON(w, networkUsageResponse{
		Usage:         samples,
		TotalCount:    len(samples),
		ReturnedCount: len(samples),
		Sampling:      samplingMeta(strategy, len(samples)),
		Metadata: networkUsageMetadata{
			ActiveInterfacesCount: len(interfaceList),
			InterfaceList:         interfaceList,
		},
		QueryTime: queryTimeSince(start),
	})
}

// monitoringIPAddress is one live IP-address assignment row.
type monitoringIPAddress struct {
	AddrObj   string `json:"addrobj"`
	Interface string `json:"interface"`
	Addr      string `json:"addr"`
	IPVersion string `json:"ip_version"`
	State     string `json:"state"`
	Source    string `json:"source"`
}

// monitoringIPPage is the IP listing's pagination block.
type monitoringIPPage struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// monitoringIPAddressesResponse is GET /monitoring/network/ipaddresses'
// answer.
type monitoringIPAddressesResponse struct {
	Addresses  []monitoringIPAddress `json:"addresses"`
	Returned   int                   `json:"returned"`
	Pagination monitoringIPPage      `json:"pagination"`
}

// @Summary		IP address assignments
// @Description	Minimum role: viewer. Live view derived from the interface list (the reduced live shape — this agent has no ipadm address-object database).
// @Tags			Host Monitoring
// @Produce		json
// @Param			limit		query	int		false	"Maximum rows"	default(100)
// @Param			offset		query	int		false	"Page offset"	default(0)
// @Param			interface	query	string	false	"Filter by interface name"
// @Param			ip_version	query	string	false	"Filter by IP version (v4 | v6)"
// @Success		200	{object}	monitoringIPAddressesResponse	"IP addresses"
// @Failure		500	{object}	wrappedError					"Failed to get IP addresses"
// @Router			/monitoring/network/ipaddresses [get]
func (s *Server) handleMonitoringIPAddresses(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)
	interfaces, err := s.monitor.Sampler().Interfaces(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get IP addresses", err.Error())
		return
	}

	wantVersion := r.URL.Query().Get("ip_version")
	wantInterface := r.URL.Query().Get("interface")
	addresses := []monitoringIPAddress{}
	for _, iface := range interfaces {
		if wantInterface != "" && iface.Link != wantInterface {
			continue
		}
		for _, addr := range iface.Addresses {
			ipVersion := "v4"
			if strings.Contains(addr, ":") {
				ipVersion = "v6"
			}
			if wantVersion != "" && ipVersion != wantVersion {
				continue
			}
			state := "ok"
			if iface.State != "up" {
				state = "down"
			}
			addresses = append(addresses, monitoringIPAddress{
				AddrObj:   iface.Link + "/" + ipVersion,
				Interface: iface.Link,
				Addr:      addr,
				IPVersion: ipVersion,
				State:     state,
				Source:    "live",
			})
		}
	}

	total := len(addresses)
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	if offset > total {
		offset = total
	}
	end := offset + q.limit
	if end > total {
		end = total
	}

	writeJSON(w, monitoringIPAddressesResponse{
		Addresses: addresses[offset:end],
		Returned:  end - offset,
		Pagination: monitoringIPPage{
			Limit:  q.limit,
			Offset: offset,
		},
	})
}

// lowSwapHost is one host row in the low-swap listing.
type lowSwapHost struct {
	Host               string    `json:"host"`
	SwapTotalGB        string    `json:"swap_total_gb"`
	SwapUsedGB         string    `json:"swap_used_gb"`
	SwapUtilizationPct float64   `json:"swap_utilization_pct"`
	LastChecked        time.Time `json:"last_checked"`
}

// lowSwapHostsResponse is GET /monitoring/hosts/low-swap's answer.
type lowSwapHostsResponse struct {
	HostsWithLowSwap []lowSwapHost `json:"hostsWithLowSwap"`
	TotalCount       int           `json:"totalCount"`
	Threshold        float64       `json:"threshold"`
}

// handleLowSwapHosts mirrors GET /monitoring/hosts/low-swap for the
// single-host case: this host appears in the list when its live swap
// utilization exceeds the threshold.
//
//	@Summary		Hosts above the swap-utilization threshold
//	@Description	Minimum role: viewer. Single-host agent: this host appears in the list when its live swap utilization exceeds the threshold.
//	@Tags			Swap Management
//	@Produce		json
//	@Param			threshold	query	number	false	"Utilization threshold percentage"	default(50)
//	@Success		200	{object}	lowSwapHostsResponse	"Hosts with low swap space"
//	@Router			/monitoring/hosts/low-swap [get]
func (s *Server) handleLowSwapHosts(w http.ResponseWriter, r *http.Request) {
	threshold := 50.0
	if raw := r.URL.Query().Get("threshold"); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			threshold = parsed
		}
	}

	sample, err := s.monitor.Sampler().SampleMemory(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get hosts with low swap", err.Error())
		return
	}

	hosts := []lowSwapHost{}
	if sample.SwapUtilizationPct > threshold {
		hosts = append(hosts, lowSwapHost{
			Host:               sample.Host,
			SwapTotalGB:        gbString(sample.SwapTotalBytes),
			SwapUsedGB:         gbString(sample.SwapUsedBytes),
			SwapUtilizationPct: sample.SwapUtilizationPct,
			LastChecked:        sample.ScanTimestamp,
		})
	}
	writeJSON(w, lowSwapHostsResponse{
		HostsWithLowSwap: hosts,
		TotalCount:       len(hosts),
		Threshold:        threshold,
	})
}
