package server

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Per-machine usage metrics (Mark's ask, sync 2026-07-19) — VirtualBox's OWN
// telemetry, never host-OS process tracking: CPU/RAM from the metrics
// subsystem the Manager GUI's Resource Use tab reads, network/disk from the VM
// debugger's cumulative byte counters, diffed into rates between polls exactly
// like the GUI. Realtime only — one live sample per RUNNING machine; stopped
// machines have no VM process and are absent. The wire mirrors zoneweaver's
// GET /monitoring/zones/usage answer ({usage, totalCount, returnedCount}) with
// this agent's machine_name filter and sampling block.

type machineUsageSample struct {
	Host                string   `json:"host"`
	MachineName         string   `json:"machine_name"`
	CPUGuestPct         *float64 `json:"cpu_guest_pct"`
	CPUVMMPct           *float64 `json:"cpu_vmm_pct"`
	CPUPct              *float64 `json:"cpu_pct"`
	RSSBytes            *int64   `json:"rss_bytes"`
	RAMTotalBytes       *int64   `json:"ram_total_bytes"`
	RAMFreeBytes        *int64   `json:"ram_free_bytes"`
	GuestAdditions      bool     `json:"guest_additions"`
	NetRxBps            *int64   `json:"net_rx_bps"`
	NetTxBps            *int64   `json:"net_tx_bps"`
	NetRxTotalBytes     *int64   `json:"net_rx_total_bytes"`
	NetTxTotalBytes     *int64   `json:"net_tx_total_bytes"`
	DiskReadBps         *int64   `json:"disk_read_bps"`
	DiskWriteBps        *int64   `json:"disk_write_bps"`
	DiskReadTotalBytes  *int64   `json:"disk_read_total_bytes"`
	DiskWriteTotalBytes *int64   `json:"disk_write_total_bytes"`
	// Nics is the PER-ADAPTER traffic split (the topology edge-width feed,
	// sync 2026-07-19) — one row per network device instance; rates null on
	// the first observation, adapter joins devices.nics[].adapter.
	Nics          []machineNicUsage `json:"nics,omitempty"`
	ScanTimestamp time.Time         `json:"scan_timestamp"`
}

type machineNicUsage struct {
	Adapter      int    `json:"adapter"`
	Device       string `json:"device"`
	RxBps        *int64 `json:"rx_bps"`
	TxBps        *int64 `json:"tx_bps"`
	RxTotalBytes int64  `json:"rx_total_bytes"`
	TxTotalBytes int64  `json:"tx_total_bytes"`
}

// machineUsageResponse is GET /monitoring/machines/usage's answer — the
// zoneweaver-shaped envelope (the usage rows plus counts and this agent's
// sampling block), mirroring zoneweaver's GET /monitoring/zones/usage.
type machineUsageResponse struct {
	Usage         []*machineUsageSample `json:"usage"`
	TotalCount    int                   `json:"totalCount"`
	ReturnedCount int                   `json:"returnedCount"`
	Sampling      machineUsageSampling  `json:"sampling"`
}

// machineUsageSampling is the realtime sampling metadata — this agent never
// downsamples, so applied is always false and strategy always "realtime".
type machineUsageSampling struct {
	Applied         bool   `json:"applied"`
	Strategy        string `json:"strategy"`
	SamplesReturned int    `json:"samplesReturned"`
}

// machineMetricsState carries the in-memory bookkeeping the realtime answers
// need: which machines already got `metrics setup` (collection is off until
// then — the first answer after a setup reports null CPU/RAM while VirtualBox
// warms up), and each machine's previous counter observation for the rate
// diffs. Dies with the agent; a machine restart resets its counters and the
// rate math skips the wrapped interval.
type machineMetricsState struct {
	mu       sync.Mutex
	setup    map[string]bool
	previous map[string]counterObservation
}

type counterObservation struct {
	at       time.Time
	counters vbox.VMCounters
}

func newMachineMetricsState() *machineMetricsState {
	return &machineMetricsState{
		setup:    map[string]bool{},
		previous: map[string]counterObservation{},
	}
}

// handleMachineUsageMetrics serves GET /monitoring/machines/usage.
//
//	@Summary		Per-machine usage metrics
//	@Description	Minimum role: viewer. Per-machine CPU/RAM/network/disk usage from VirtualBox's OWN telemetry (Mark's ruling, sync 2026-07-19 — never host-OS process tracking): CPU and RAM from the metrics subsystem the Manager GUI's Resource Use tab reads (VBoxManage metrics — the agent runs `metrics setup --period 1 --samples 1` lazily per machine, so the FIRST answer after an agent or machine start can carry null CPU/RAM while collection warms up for a second), network and disk from the VM debugger's cumulative byte counters (VBoxManage debugvm statistics — ReceiveBytes/TransmitBytes/ReadBytes/WrittenBytes summed across devices), diffed into per-second rates between polls exactly like the GUI (rates are null on the first observation and across a VM restart's counter reset; totals are since the VM process started). REALTIME ONLY — one live sample per RUNNING machine, newest state every call; stopped machines have no VM process and are ABSENT from the answer (poll the list — presence = running). RAM'S GUEST-ADDITIONS DEPENDENCY (the GUI's "requires guest additions" banner): rss_bytes/ram_total_bytes/ram_free_bytes are null when the guest reports nothing, and guest_additions says whether any Guest/* metric answered — the UI renders the same honest blank the GUI does. The answer mirrors zoneweaver's GET /monitoring/zones/usage envelope ({usage, totalCount, returnedCount} + this agent's sampling block); the sample vocabulary matches where the platforms overlap (host, machine_name for zone_name, cpu_pct = percent of TOTAL host CPU, rss_bytes) and speaks VirtualBox where they differ (guest-vs-VMM CPU split, net/disk rates — zoneweaver's disk I/O is per-ZVOL on its own endpoint).
//	@Tags			Host Monitoring
//	@Produce		json
//	@Param			machine_name	query	string	false	"Filter to one machine (exact name)"
//	@Param			limit	query	int	false	"Maximum rows"	default(200)	minimum(1)	maximum(1000)
//	@Success		200	{object}	machineUsageResponse	"Per-machine usage samples (running machines only)"
//	@Failure		500	"Failed to get machine metrics"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/monitoring/machines/usage [get]
func (s *Server) handleMachineUsageMetrics(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = min(max(n, 1), 1000)
		}
	}
	nameFilter := r.URL.Query().Get("machine_name")

	list, err := s.machines.List(r.Context(), &machines.ListFilter{})
	if err != nil {
		slog.Error("list machines for usage metrics", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to get machine metrics")
		return
	}
	running, err := vbox.ListRegistered(r.Context(), exe, "runningvms")
	if err != nil {
		slog.Error("list running machines for usage metrics", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to get machine metrics")
		return
	}
	runningUUIDs := map[string]bool{}
	runningNames := map[string]bool{}
	for _, reg := range running {
		runningUUIDs[strings.ToLower(reg.UUID)] = true
		runningNames[reg.Name] = true
	}

	hostname, herr := os.Hostname()
	if herr != nil {
		hostname = "unknown"
	}
	now := time.Now()
	samples := []*machineUsageSample{}
	for _, machine := range list {
		if nameFilter != "" && machine.Name != nameFilter {
			continue
		}
		isRunning := runningNames[machine.Name]
		if machine.UUID != nil && runningUUIDs[strings.ToLower(*machine.UUID)] {
			isRunning = true
		}
		if !isRunning {
			continue
		}
		samples = append(samples, s.machineUsage(r, exe, hostname, machine, now))
		if len(samples) >= limit {
			break
		}
	}

	writeJSON(w, machineUsageResponse{
		Usage:         samples,
		TotalCount:    len(samples),
		ReturnedCount: len(samples),
		Sampling: machineUsageSampling{
			Applied:         false,
			Strategy:        "realtime",
			SamplesReturned: len(samples),
		},
	})
}

// machineUsage builds one machine's sample from the two native facilities;
// either facility failing just leaves its fields null — a partial answer beats
// none.
func (s *Server) machineUsage(r *http.Request, exe, hostname string,
	machine *machines.Machine, now time.Time,
) *machineUsageSample {
	sample := &machineUsageSample{Host: hostname, MachineName: machine.Name, ScanTimestamp: now}
	target := machine.VBoxTarget()
	ctx := r.Context()

	s.machineMetrics.mu.Lock()
	needsSetup := !s.machineMetrics.setup[machine.Name]
	s.machineMetrics.mu.Unlock()
	if needsSetup {
		if serr := vbox.MetricsSetup(ctx, exe, target); serr != nil {
			slog.Debug("metrics setup failed", "machine", machine.Name, "error", serr)
		} else {
			s.machineMetrics.mu.Lock()
			s.machineMetrics.setup[machine.Name] = true
			s.machineMetrics.mu.Unlock()
		}
	}

	if values, err := vbox.MetricsQuery(ctx, exe, target); err == nil {
		guest, gok := vbox.MetricPercent(values["CPU/Load/User"])
		vmm, vok := vbox.MetricPercent(values["CPU/Load/Kernel"])
		if gok {
			sample.CPUGuestPct = &guest
		}
		if vok {
			sample.CPUVMMPct = &vmm
		}
		if gok || vok {
			total := guest + vmm
			sample.CPUPct = &total
		}
		for key := range values {
			if strings.HasPrefix(key, "Guest/") {
				sample.GuestAdditions = true
				break
			}
		}
		if used, ok := vbox.MetricKilobytes(values["RAM/Usage/Used"]); ok {
			sample.RSSBytes = &used
		}
		if total, ok := vbox.MetricKilobytes(values["Guest/RAM/Usage/Total"]); ok {
			sample.RAMTotalBytes = &total
		}
		if free, ok := vbox.MetricKilobytes(values["Guest/RAM/Usage/Free"]); ok {
			sample.RAMFreeBytes = &free
		}
		if sample.RSSBytes == nil && sample.RAMTotalBytes != nil && sample.RAMFreeBytes != nil {
			used := *sample.RAMTotalBytes - *sample.RAMFreeBytes
			sample.RSSBytes = &used
		}
	} else {
		slog.Debug("metrics query failed", "machine", machine.Name, "error", err)
	}

	counters, cerr := vbox.DebugVMCounters(ctx, exe, target)
	if cerr != nil {
		slog.Debug("debugvm counters failed", "machine", machine.Name, "error", cerr)
		return sample
	}
	if counters.HasNet {
		rx, tx := counters.NetRxBytes, counters.NetTxBytes
		sample.NetRxTotalBytes, sample.NetTxTotalBytes = &rx, &tx
		for _, device := range counters.PerNet {
			sample.Nics = append(sample.Nics, machineNicUsage{
				Adapter:      device.Adapter,
				Device:       device.Device,
				RxTotalBytes: device.RxBytes,
				TxTotalBytes: device.TxBytes,
			})
		}
	}
	if counters.HasDisk {
		read, written := counters.DiskReadBytes, counters.DiskWrittenBytes
		sample.DiskReadTotalBytes, sample.DiskWriteTotalBytes = &read, &written
	}

	s.machineMetrics.mu.Lock()
	prev, hasPrev := s.machineMetrics.previous[machine.Name]
	s.machineMetrics.previous[machine.Name] = counterObservation{at: now, counters: *counters}
	s.machineMetrics.mu.Unlock()
	if !hasPrev {
		return sample
	}
	elapsed := now.Sub(prev.at).Seconds()
	if elapsed <= 0 {
		return sample
	}
	rate := func(current, previous int64) *int64 {
		if current < previous {
			return nil
		}
		v := int64(float64(current-previous) / elapsed)
		return &v
	}
	if counters.HasNet && prev.counters.HasNet {
		sample.NetRxBps = rate(counters.NetRxBytes, prev.counters.NetRxBytes)
		sample.NetTxBps = rate(counters.NetTxBytes, prev.counters.NetTxBytes)
		prevNet := map[string]vbox.NetDeviceCounters{}
		for _, device := range prev.counters.PerNet {
			prevNet[device.Device] = device
		}
		for i := range sample.Nics {
			before, seen := prevNet[sample.Nics[i].Device]
			if !seen {
				continue
			}
			sample.Nics[i].RxBps = rate(sample.Nics[i].RxTotalBytes, before.RxBytes)
			sample.Nics[i].TxBps = rate(sample.Nics[i].TxTotalBytes, before.TxBytes)
		}
	}
	if counters.HasDisk && prev.counters.HasDisk {
		sample.DiskReadBps = rate(counters.DiskReadBytes, prev.counters.DiskReadBytes)
		sample.DiskWriteBps = rate(counters.DiskWrittenBytes, prev.counters.DiskWrittenBytes)
	}
	return sample
}
