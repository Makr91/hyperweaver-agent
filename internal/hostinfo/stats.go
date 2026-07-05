package hostinfo

import (
	"log/slog"
	"runtime"
	"sync"

	sysinfo "github.com/elastic/go-sysinfo"
	"github.com/elastic/go-sysinfo/types"
)

// The GET /stats probes are backed by elastic/go-sysinfo — a maintained,
// cross-OS host-introspection library — instead of hand-rolled syscalls, so
// the Linux and macOS paths ship tested (the darwin sysctl parsing in
// particular is not testable in this project's dev environment). The handle
// is cheap and stateless; its methods read live values on each call.

var (
	hostOnce   sync.Once
	hostHandle types.Host
)

func host() types.Host {
	hostOnce.Do(func() {
		h, err := sysinfo.Host()
		if err != nil {
			slog.Error("host introspection unavailable; /stats serves zero values", "error", err)
			return
		}
		hostHandle = h
	})
	return hostHandle
}

// Type returns Node's os.type() vocabulary for this platform (the shared v1
// stats shape): Windows_NT, Linux, or Darwin.
func Type() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows_NT"
	case "darwin":
		return "Darwin"
	case "linux":
		return "Linux"
	default:
		return runtime.GOOS
	}
}

// KernelRelease returns the kernel version string (Node's os.release()).
func KernelRelease() string {
	h := host()
	if h == nil {
		return ""
	}
	return h.Info().KernelVersion
}

// UptimeSeconds returns seconds since host boot (not process start).
func UptimeSeconds() uint64 {
	h := host()
	if h == nil {
		return 0
	}
	up := h.Info().Uptime()
	if up < 0 {
		return 0
	}
	return uint64(up.Seconds())
}

// MemoryStatus returns total and available physical memory in bytes — the
// values Node's totalmem/freemem report.
func MemoryStatus() (total, free uint64) {
	h := host()
	if h == nil {
		return 0, 0
	}
	mem, err := h.Memory()
	if err != nil || mem == nil {
		return 0, 0
	}
	return mem.Total, mem.Available
}

// LoadAvg returns the 1/5/15-minute load averages. Zeros on platforms
// without the concept (Windows — Node's os.loadavg() reports zeros there
// too).
func LoadAvg() [3]float64 {
	h := host()
	if h == nil {
		return [3]float64{}
	}
	la, ok := h.(types.LoadAverage)
	if !ok {
		return [3]float64{}
	}
	avg, err := la.LoadAverage()
	if err != nil || avg == nil {
		return [3]float64{}
	}
	return [3]float64{avg.One, avg.Five, avg.Fifteen}
}
