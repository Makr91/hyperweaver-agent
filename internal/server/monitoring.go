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

// samplingMeta is the time-series sampling metadata block: this agent never
// downsamples, so applied is always false — the strategy names which mode
// answered (realtime = single live sample, stored = database rows).
func samplingMeta(strategy string, returned int) map[string]any {
	return map[string]any{
		"applied":         false,
		"strategy":        strategy,
		"samplesReturned": returned,
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

	payload := map[string]any{
		"cpu":           samples,
		"totalCount":    len(samples),
		"returnedCount": len(samples),
		"sampling":      samplingMeta(strategy, len(samples)),
		"queryTime":     queryTimeSince(start),
	}
	if len(samples) > 0 {
		payload["latest"] = samples[0]
	} else {
		payload["latest"] = nil
	}
	writeJSON(w, payload)
}

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

	payload := map[string]any{
		"memory":        samples,
		"totalCount":    len(samples),
		"returnedCount": len(samples),
		"sampling":      samplingMeta(strategy, len(samples)),
		"queryTime":     queryTimeSince(start),
	}
	if len(samples) > 0 {
		payload["latest"] = samples[0]
	} else {
		payload["latest"] = nil
	}
	writeJSON(w, payload)
}

// loadEntry reshapes a CPU sample into the load-metrics chart shape (the
// Node agent's /monitoring/system/load items). Activity counters the
// platform does not report stay zero.
func loadEntry(sample *monitoring.CPUSample) map[string]any {
	return map[string]any{
		"timestamp": sample.ScanTimestamp,
		"load_averages": map[string]any{
			"one_min":     sample.LoadAvg1Min,
			"five_min":    sample.LoadAvg5Min,
			"fifteen_min": sample.LoadAvg15Min,
		},
		"process_activity": map[string]any{
			"running": sample.ProcessesRunning,
			"blocked": sample.ProcessesBlocked,
		},
		"cpu_count": sample.CPUCount,
	}
}

func (s *Server) handleMonitoringLoad(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)

	samples, _, err := s.cpuSamples(r, q)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get system load metrics", err.Error())
		return
	}

	entries := make([]map[string]any, 0, len(samples))
	for i := range samples {
		entries = append(entries, loadEntry(&samples[i]))
	}
	payload := map[string]any{
		"load":       entries,
		"totalCount": len(entries),
		"metadata": map[string]any{
			"description": "Load averages and process activity (load averages are zeros on Windows — the platform has no concept)",
			"metrics_included": []string{
				"load_averages", "process_activity", "cpu_count",
			},
		},
	}
	if len(entries) > 0 {
		payload["latest"] = entries[0]
	} else {
		payload["latest"] = nil
	}
	writeJSON(w, payload)
}

func (s *Server) handleMonitoringHost(w http.ResponseWriter, _ *http.Request) {
	info := hostinfo.Get()
	payload := map[string]any{
		"host":            s.monitor.Sampler().Hostname(),
		"hostname":        s.monitor.Sampler().Hostname(),
		"platform":        nodePlatform(),
		"release":         hostinfo.KernelRelease(),
		"arch":            info.Arch,
		"uptime":          hostinfo.UptimeSeconds(),
		"os":              info.OS,
		"cpus":            info.CPUs,
		"memory_bytes":    info.MemoryBytes,
		"storage_enabled": s.monitor.StorageEnabled(),
	}
	if last := s.monitor.LastCollection(); !last.IsZero() {
		payload["last_collection"] = last.UTC().Format(time.RFC3339)
	} else {
		payload["last_collection"] = nil
	}
	writeJSON(w, payload)
}

func (s *Server) handleMonitoringSummary(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	payload := map[string]any{
		"host": s.monitor.Sampler().Hostname(),
		"summary": map[string]any{
			"storage_enabled": s.monitor.StorageEnabled(),
			"collector":       s.monitor.Running(),
		},
	}

	if s.monitor.StorageEnabled() {
		counts, latest, err := s.monitor.Store().Counts(r.Context())
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, "Failed to get monitoring summary", err.Error())
			return
		}
		payload["recordCounts"] = counts
		latestData := map[string]any{}
		for table, at := range latest {
			if at != nil {
				latestData[table] = at.UTC().Format(time.RFC3339)
			}
		}
		payload["latestData"] = latestData
	} else {
		payload["recordCounts"] = map[string]int64{}
		payload["latestData"] = map[string]any{}
	}
	if last := s.monitor.LastCollection(); !last.IsZero() {
		payload["lastCollected"] = last.UTC().Format(time.RFC3339)
	} else {
		payload["lastCollected"] = nil
	}
	payload["queryTime"] = queryTimeSince(start)
	writeJSON(w, payload)
}

func (s *Server) handleMonitoringStatus(w http.ResponseWriter, _ *http.Request) {
	note := "Realtime mode: every request samples the OS live; enable monitoring.storage_enabled for stored history."
	if s.monitor.StorageEnabled() {
		note = "Storage mode: a background collector writes time series into per-datatype database files."
	}
	writeJSON(w, map[string]any{
		"isRunning":     s.monitor.Running() || !s.monitor.StorageEnabled(),
		"isInitialized": true,
		"config": map[string]any{
			"storage_enabled":     s.cfg.Monitoring.StorageEnabled,
			"collection_interval": s.cfg.Monitoring.CollectionInterval,
			"retention_days":      s.cfg.Monitoring.RetentionDays,
		},
		"stats": s.monitor.Stats(),
		"note":  note,
	})
}

func (s *Server) handleMonitoringHealth(w http.ResponseWriter, _ *http.Request) {
	status := "healthy"
	if s.monitor.StorageEnabled() && !s.monitor.Running() {
		status = "stopped"
	}
	stats := s.monitor.Stats()
	if _, hadError := stats["last_error"]; hadError && status == "healthy" {
		status = "degraded"
	}

	payload := map[string]any{
		"status":  status,
		"uptime":  hostinfo.UptimeSeconds(),
		"version": version.Version,
		"service": map[string]any{
			"storage_enabled": s.monitor.StorageEnabled(),
			"collector":       s.monitor.Running(),
			"stats":           stats,
		},
	}
	if last := s.monitor.LastCollection(); !last.IsZero() {
		payload["lastUpdate"] = last.UTC().Format(time.RFC3339)
	} else {
		payload["lastUpdate"] = nil
	}
	writeJSON(w, payload)
}

func (s *Server) handleMonitoringCollect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type string `json:"type"`
	}
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
	writeJSON(w, map[string]any{
		"success": true,
		"type":    collectionType,
		"results": results,
	})
}

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

	writeJSON(w, map[string]any{
		"interfaces": interfaces[offset:end],
		"totalCount": total,
		"pagination": map[string]any{
			"limit":   q.limit,
			"offset":  offset,
			"hasMore": total > end,
		},
	})
}

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

	writeJSON(w, map[string]any{
		"usage":         samples,
		"totalCount":    len(samples),
		"returnedCount": len(samples),
		"sampling":      samplingMeta(strategy, len(samples)),
		"metadata": map[string]any{
			"activeInterfacesCount": len(interfaceList),
			"interfaceList":         interfaceList,
		},
		"queryTime": queryTimeSince(start),
	})
}

func (s *Server) handleMonitoringIPAddresses(w http.ResponseWriter, r *http.Request) {
	q := parseMonitoringQuery(r)
	interfaces, err := s.monitor.Sampler().Interfaces(r.Context())
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to get IP addresses", err.Error())
		return
	}

	wantVersion := r.URL.Query().Get("ip_version")
	wantInterface := r.URL.Query().Get("interface")
	addresses := []map[string]any{}
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
			addresses = append(addresses, map[string]any{
				"addrobj":    iface.Link + "/" + ipVersion,
				"interface":  iface.Link,
				"addr":       addr,
				"ip_version": ipVersion,
				"state":      state,
				"source":     "live",
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

	writeJSON(w, map[string]any{
		"addresses": addresses[offset:end],
		"returned":  end - offset,
		"pagination": map[string]any{
			"limit":  q.limit,
			"offset": offset,
		},
	})
}

// handleLowSwapHosts mirrors GET /monitoring/hosts/low-swap for the
// single-host case: this host appears in the list when its live swap
// utilization exceeds the threshold.
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

	hosts := []map[string]any{}
	if sample.SwapUtilizationPct > threshold {
		hosts = append(hosts, map[string]any{
			"host":                 sample.Host,
			"swap_total_gb":        gbString(sample.SwapTotalBytes),
			"swap_used_gb":         gbString(sample.SwapUsedBytes),
			"swap_utilization_pct": sample.SwapUtilizationPct,
			"last_checked":         sample.ScanTimestamp,
		})
	}
	writeJSON(w, map[string]any{
		"hostsWithLowSwap": hosts,
		"totalCount":       len(hosts),
		"threshold":        threshold,
	})
}
