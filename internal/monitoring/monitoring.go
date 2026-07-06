// Package monitoring implements the agent's host telemetry surface
// (/monitoring/*, the `monitoring` capability token) — the Node
// zoneweaver-agent's HostMonitoringService reshaped per Mark's 2026-07-05
// ruling: the endpoints ALWAYS serve realtime samples read live through
// gopsutil; enabling monitoring.storage_enabled adds a background collector
// writing time series into per-datatype SQLite files so history charts work.
// Illumos-only families (ZFS pools/datasets/ARC, disk IO via zpool iostat)
// have no analog here and are deliberately absent.
package monitoring

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gopsnet "github.com/shirou/gopsutil/v4/net"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

// monlog is this package's category logger (logging.categories.monitoring
// overrides its level).
func monlog() *slog.Logger {
	return logging.Category("monitoring")
}

// CoreUsage is one logical CPU's utilization in a sample — the parsed form
// the Node agent serves as per_core_parsed when include_cores=true.
type CoreUsage struct {
	Core           int     `json:"core"`
	UtilizationPct float64 `json:"utilization_pct"`
	UserPct        float64 `json:"user_pct"`
	SystemPct      float64 `json:"system_pct"`
	IdlePct        float64 `json:"idle_pct"`
}

// CPUSample is one CPU telemetry observation (the CPUStats schema's
// platform-feasible subset; illumos-only counters stay zero).
type CPUSample struct {
	Host              string      `json:"host"`
	CPUCount          int         `json:"cpu_count"`
	CPUUtilizationPct float64     `json:"cpu_utilization_pct"`
	UserPct           float64     `json:"user_pct"`
	SystemPct         float64     `json:"system_pct"`
	IdlePct           float64     `json:"idle_pct"`
	LoadAvg1Min       float64     `json:"load_avg_1min"`
	LoadAvg5Min       float64     `json:"load_avg_5min"`
	LoadAvg15Min      float64     `json:"load_avg_15min"`
	ProcessesRunning  int         `json:"processes_running"`
	ProcessesBlocked  int         `json:"processes_blocked"`
	PerCoreParsed     []CoreUsage `json:"per_core_parsed,omitempty"`
	ScanTimestamp     time.Time   `json:"scan_timestamp"`
}

// MemorySample is one memory telemetry observation (the MemoryStats schema's
// platform-feasible subset; ZFS ARC fields have no analog and stay absent).
type MemorySample struct {
	Host                 string    `json:"host"`
	TotalMemoryBytes     uint64    `json:"total_memory_bytes"`
	AvailableMemoryBytes uint64    `json:"available_memory_bytes"`
	UsedMemoryBytes      uint64    `json:"used_memory_bytes"`
	FreeMemoryBytes      uint64    `json:"free_memory_bytes"`
	MemoryUtilizationPct float64   `json:"memory_utilization_pct"`
	SwapTotalBytes       uint64    `json:"swap_total_bytes"`
	SwapUsedBytes        uint64    `json:"swap_used_bytes"`
	SwapFreeBytes        uint64    `json:"swap_free_bytes"`
	SwapUtilizationPct   float64   `json:"swap_utilization_pct"`
	ScanTimestamp        time.Time `json:"scan_timestamp"`
}

// NetworkSample is one interface's telemetry observation (the NetworkUsage
// schema's platform-feasible subset): cumulative counters plus rates
// computed from the previous observation.
type NetworkSample struct {
	Host             string    `json:"host"`
	Link             string    `json:"link"`
	IPackets         uint64    `json:"ipackets"`
	RBytes           uint64    `json:"rbytes"`
	IErrors          uint64    `json:"ierrors"`
	OPackets         uint64    `json:"opackets"`
	OBytes           uint64    `json:"obytes"`
	OErrors          uint64    `json:"oerrors"`
	RxBps            uint64    `json:"rx_bps"`
	TxBps            uint64    `json:"tx_bps"`
	RxMbps           float64   `json:"rx_mbps"`
	TxMbps           float64   `json:"tx_mbps"`
	TimeDeltaSeconds float64   `json:"time_delta_seconds"`
	ScanTimestamp    time.Time `json:"scan_timestamp"`
}

// Interface is one network interface's configuration view (the
// NetworkInterface schema's platform-feasible subset; dladm-only fields stay
// absent).
type Interface struct {
	Link       string   `json:"link"`
	Class      string   `json:"class"`
	MTU        int      `json:"mtu"`
	State      string   `json:"state"`
	MACAddress string   `json:"macaddress"`
	Addresses  []string `json:"addresses"`
}

// Sampler reads live telemetry. Rate values (CPU percentages, network bps)
// are deltas against the previous observation, so the sampler keeps the last
// raw counters in memory — process state, not storage. The very first
// observation takes a short two-point sample instead.
type Sampler struct {
	hostname string

	mu           sync.Mutex
	lastCPUTimes []cpu.TimesStat
	lastCPUAt    time.Time
	lastNet      map[string]gopsnet.IOCountersStat
	lastNetAt    time.Time
}

// NewSampler builds the live sampler.
func NewSampler() *Sampler {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return &Sampler{hostname: hostname}
}

// firstSampleWindow is the two-point window used when no previous
// observation exists (the first request or collector tick after boot).
const firstSampleWindow = 250 * time.Millisecond

func round2(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*100) / 100
}

// cpuBusyPcts computes per-interval utilization percentages from two
// cumulative Times observations.
func cpuBusyPcts(prev, curr *cpu.TimesStat) (total, user, system, idle float64) {
	dUser := curr.User - prev.User
	dSystem := curr.System - prev.System
	dIdle := curr.Idle - prev.Idle
	dBusy := dUser + dSystem + (curr.Nice - prev.Nice) + (curr.Irq - prev.Irq) +
		(curr.Softirq - prev.Softirq) + (curr.Steal - prev.Steal) + (curr.Iowait - prev.Iowait)
	span := dBusy + dIdle
	if span <= 0 {
		return 0, 0, 0, 100
	}
	return round2(dBusy / span * 100), round2(dUser / span * 100),
		round2(dSystem / span * 100), round2(dIdle / span * 100)
}

// SampleCPU takes one CPU observation: utilization from the delta against
// the previous observation, load averages (zeros on Windows), and process
// counts where the platform reports them.
func (s *Sampler) SampleCPU(ctx context.Context) (*CPUSample, error) {
	curr, err := cpu.TimesWithContext(ctx, true)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	prev := s.lastCPUTimes
	s.mu.Unlock()

	if len(prev) != len(curr) {
		// First observation (or a hotplug changed the core count): take the
		// short two-point window so the numbers are real, not garbage.
		prev = curr
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(firstSampleWindow):
		}
		curr, err = cpu.TimesWithContext(ctx, true)
		if err != nil {
			return nil, err
		}
		if len(prev) != len(curr) {
			prev = curr
		}
	}

	s.mu.Lock()
	s.lastCPUTimes = curr
	s.lastCPUAt = time.Now()
	s.mu.Unlock()

	sample := &CPUSample{
		Host:          s.hostname,
		CPUCount:      len(curr),
		ScanTimestamp: time.Now().UTC(),
	}

	var prevAgg, currAgg cpu.TimesStat
	cores := make([]CoreUsage, 0, len(curr))
	for i := range curr {
		p := &prev[i]
		c := &curr[i]
		prevAgg.User += p.User
		prevAgg.System += p.System
		prevAgg.Idle += p.Idle
		prevAgg.Nice += p.Nice
		prevAgg.Irq += p.Irq
		prevAgg.Softirq += p.Softirq
		prevAgg.Steal += p.Steal
		prevAgg.Iowait += p.Iowait
		currAgg.User += c.User
		currAgg.System += c.System
		currAgg.Idle += c.Idle
		currAgg.Nice += c.Nice
		currAgg.Irq += c.Irq
		currAgg.Softirq += c.Softirq
		currAgg.Steal += c.Steal
		currAgg.Iowait += c.Iowait

		total, user, system, idle := cpuBusyPcts(p, c)
		cores = append(cores, CoreUsage{
			Core:           i,
			UtilizationPct: total,
			UserPct:        user,
			SystemPct:      system,
			IdlePct:        idle,
		})
	}
	sample.PerCoreParsed = cores
	sample.CPUUtilizationPct, sample.UserPct, sample.SystemPct, sample.IdlePct = cpuBusyPcts(&prevAgg, &currAgg)

	// Load averages: zeros on Windows (the platform has no concept — same
	// answer Node's os.loadavg() gives there).
	if avg, lerr := load.AvgWithContext(ctx); lerr == nil && avg != nil {
		sample.LoadAvg1Min = round2(avg.Load1)
		sample.LoadAvg5Min = round2(avg.Load5)
		sample.LoadAvg15Min = round2(avg.Load15)
	}
	// Process run-queue counts: Linux only in gopsutil; zeros elsewhere.
	if misc, merr := load.MiscWithContext(ctx); merr == nil && misc != nil {
		sample.ProcessesRunning = misc.ProcsRunning
		sample.ProcessesBlocked = misc.ProcsBlocked
	}
	return sample, nil
}

// SampleMemory takes one memory + swap observation (stateless).
func (s *Sampler) SampleMemory(ctx context.Context) (*MemorySample, error) {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return nil, err
	}
	sample := &MemorySample{
		Host:                 s.hostname,
		TotalMemoryBytes:     vm.Total,
		AvailableMemoryBytes: vm.Available,
		UsedMemoryBytes:      vm.Used,
		FreeMemoryBytes:      vm.Free,
		MemoryUtilizationPct: round2(vm.UsedPercent),
		ScanTimestamp:        time.Now().UTC(),
	}
	if swap, serr := mem.SwapMemoryWithContext(ctx); serr == nil && swap != nil {
		sample.SwapTotalBytes = swap.Total
		sample.SwapUsedBytes = swap.Used
		sample.SwapFreeBytes = swap.Free
		sample.SwapUtilizationPct = round2(swap.UsedPercent)
	}
	return sample, nil
}

// SampleNetwork takes one observation per active interface, with rates from
// the delta against the previous observation.
func (s *Sampler) SampleNetwork(ctx context.Context) ([]NetworkSample, error) {
	counters, err := gopsnet.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	prev := s.lastNet
	prevAt := s.lastNetAt
	s.mu.Unlock()

	if prev == nil {
		prev = indexCounters(counters)
		prevAt = time.Now()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(firstSampleWindow):
		}
		counters, err = gopsnet.IOCountersWithContext(ctx, true)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	s.mu.Lock()
	s.lastNet = indexCounters(counters)
	s.lastNetAt = now
	s.mu.Unlock()

	delta := now.Sub(prevAt).Seconds()
	timestamp := now.UTC()
	samples := make([]NetworkSample, 0, len(counters))
	for _, c := range counters {
		sample := NetworkSample{
			Host:             s.hostname,
			Link:             c.Name,
			IPackets:         c.PacketsRecv,
			RBytes:           c.BytesRecv,
			IErrors:          c.Errin,
			OPackets:         c.PacketsSent,
			OBytes:           c.BytesSent,
			OErrors:          c.Errout,
			TimeDeltaSeconds: round2(delta),
			ScanTimestamp:    timestamp,
		}
		if p, known := prev[c.Name]; known && delta > 0 {
			if c.BytesRecv >= p.BytesRecv {
				sample.RxBps = uint64(float64(c.BytesRecv-p.BytesRecv) / delta)
			}
			if c.BytesSent >= p.BytesSent {
				sample.TxBps = uint64(float64(c.BytesSent-p.BytesSent) / delta)
			}
			sample.RxMbps = round2(float64(sample.RxBps) * 8 / 1_000_000)
			sample.TxMbps = round2(float64(sample.TxBps) * 8 / 1_000_000)
		}
		samples = append(samples, sample)
	}
	return samples, nil
}

func indexCounters(counters []gopsnet.IOCountersStat) map[string]gopsnet.IOCountersStat {
	indexed := make(map[string]gopsnet.IOCountersStat, len(counters))
	for _, c := range counters {
		indexed[c.Name] = c
	}
	return indexed
}

// Interfaces lists the host's network interfaces (configuration view, not
// counters).
func (s *Sampler) Interfaces(ctx context.Context) ([]Interface, error) {
	list, err := gopsnet.InterfacesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(list))
	for _, iface := range list {
		state := "down"
		for _, flag := range iface.Flags {
			if flag == "up" {
				state = "up"
				break
			}
		}
		addrs := make([]string, 0, len(iface.Addrs))
		for _, a := range iface.Addrs {
			addrs = append(addrs, a.Addr)
		}
		out = append(out, Interface{
			Link:       iface.Name,
			Class:      "phys",
			MTU:        iface.MTU,
			State:      state,
			MACAddress: iface.HardwareAddr,
			Addresses:  addrs,
		})
	}
	return out, nil
}

// Hostname returns the sampler's cached hostname.
func (s *Sampler) Hostname() string {
	return s.hostname
}

// marshalCores serializes per-core data for storage; nil on failure (the
// column is nullable).
func marshalCores(cores []CoreUsage) []byte {
	if len(cores) == 0 {
		return nil
	}
	raw, err := json.Marshal(cores)
	if err != nil {
		monlog().Error("serialize per-core data", "error", err)
		return nil
	}
	return raw
}
