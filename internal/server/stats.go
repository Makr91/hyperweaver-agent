package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"

	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// statsPayload is the GET /stats document (the shared v1 stats shape):
// host-OS numbers in Node's os-module vocabulary plus machine name lists.
type statsPayload struct {
	Hostname string `json:"hostname"`
	EOL      string `json:"eol"`
	// Node os.arch() vocabulary
	Arch string `json:"arch"`
	// One entry per logical CPU, Node os.cpus() shape; times are cumulative milliseconds — consumers diff between polls for usage
	Cpus       []cpuEntry `json:"cpus"`
	Endianness string     `json:"endianness"`
	// Available physical memory in bytes
	Freemem uint64 `json:"freemem"`
	// 1/5/15-minute load averages (zeros on Windows)
	Loadavg [3]float64 `json:"loadavg"`
	// Node os.platform() vocabulary
	Platform string `json:"platform"`
	// Kernel version
	Release string `json:"release"`
	// Total physical memory in bytes
	Totalmem uint64 `json:"totalmem"`
	// Node os.type() vocabulary
	Type string `json:"type"`
	// Host uptime in seconds (not process uptime)
	Uptime uint64 `json:"uptime"`
	// OS marketing name
	Version string `json:"version"`
	// All registered machine names (VBoxManage list vms)
	AllMachines []string `json:"allmachines"`
	// Running machine names (VBoxManage list runningvms)
	RunningMachines []string `json:"runningmachines"`
}

// cpuEntry is one logical CPU in Node's os.cpus() shape: model string, speed
// in MHz, cumulative times in MILLISECONDS — the UI's Resource Utilization
// diffs the times between polls to compute usage.
type cpuEntry struct {
	Model string `json:"model"`
	// MHz
	Speed int      `json:"speed"`
	Times cpuTimes `json:"times"`
}

type cpuTimes struct {
	User int64 `json:"user"`
	Nice int64 `json:"nice"`
	Sys  int64 `json:"sys"`
	Idle int64 `json:"idle"`
	Irq  int64 `json:"irq"`
}

// cpuEntries builds the Node os.cpus() array: one entry per logical CPU with
// cumulative millisecond times (gopsutil reports seconds). Failures degrade
// to an empty array — same never-500 posture as the machine lists.
func cpuEntries(ctx context.Context) []cpuEntry {
	perCPU, err := cpu.TimesWithContext(ctx, true)
	if err != nil {
		slog.Warn("read per-cpu times failed", "error", err)
		return []cpuEntry{}
	}

	model := ""
	speed := 0
	if infos, ierr := cpu.InfoWithContext(ctx); ierr != nil {
		slog.Warn("read cpu info failed", "error", ierr)
	} else if len(infos) > 0 {
		model = infos[0].ModelName
		speed = int(infos[0].Mhz)
	}

	toMillis := func(seconds float64) int64 {
		return int64(seconds * 1000)
	}
	entries := make([]cpuEntry, 0, len(perCPU))
	for _, t := range perCPU {
		entries = append(entries, cpuEntry{
			Model: model,
			Speed: speed,
			Times: cpuTimes{
				User: toMillis(t.User),
				Nice: toMillis(t.Nice),
				Sys:  toMillis(t.System),
				Idle: toMillis(t.Idle),
				Irq:  toMillis(t.Irq),
			},
		})
	}
	return entries
}

// nodeArch maps GOARCH to Node's os.arch() vocabulary — the /stats contract,
// distinct from archName in status.go, which speaks the /api/status
// x86_64/aarch64 vocabulary.
func nodeArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x64"
	case "arm64":
		return "arm64"
	case "386":
		return "ia32"
	default:
		return runtime.GOARCH
	}
}

// nodePlatform maps GOOS to Node's os.platform() vocabulary.
func nodePlatform() string {
	if runtime.GOOS == "windows" {
		return "win32"
	}
	return runtime.GOOS
}

func eolString() string {
	if runtime.GOOS == "windows" {
		return "\r\n"
	}
	return "\n"
}

// vboxManagePath returns the validated VBoxManage path from the prerequisite
// detector, or "" when VirtualBox is not installed.
func vboxManagePath(ctx context.Context) string {
	for _, tool := range prereqs.Detect(ctx) {
		if tool.Name == "virtualbox" && tool.Installed {
			return tool.Path
		}
	}
	return ""
}

// handleStats mirrors the Node agent's GET /stats. Machine-list failures
// degrade to empty arrays (Node parity): a broken VBoxManage never 500s the
// host stats. The `version` field carries the OS marketing name (what Node's
// os.version() reports on Windows) rather than a raw kernel build string —
// it feeds the UI's System Information panel.
//
//	@Summary		Host statistics and machine lists
//	@Description	Minimum role: viewer — unless the agent is configured with `stats.public_access: true`, which serves this endpoint without an API key (the Node agent's conditional /stats registration). OS-level host statistics plus the registered and running VirtualBox machine name lists. Machine-list failures degrade to empty arrays — a broken VBoxManage never fails the host stats.
//	@Tags			System
//	@Produce		json
//	@Success		200	{object}	statsPayload		"Host statistics"
//	@Failure		401	{object}	map[string]string	"Missing API key"
//	@Failure		403	{object}	map[string]string	"Invalid API key"
//	@Router			/stats [get]
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	total, free := hostinfo.MemoryStatus()

	payload := statsPayload{
		Hostname:        hostname,
		EOL:             eolString(),
		Arch:            nodeArch(),
		Cpus:            cpuEntries(r.Context()),
		Endianness:      "LE",
		Freemem:         free,
		Loadavg:         hostinfo.LoadAvg(),
		Platform:        nodePlatform(),
		Release:         hostinfo.KernelRelease(),
		Totalmem:        total,
		Type:            hostinfo.Type(),
		Uptime:          hostinfo.UptimeSeconds(),
		Version:         hostinfo.Get().OS,
		AllMachines:     []string{},
		RunningMachines: []string{},
	}

	if exe := vboxManagePath(r.Context()); exe != "" {
		listCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if names, lerr := vbox.ListVMs(listCtx, exe); lerr == nil {
			payload.AllMachines = names
		} else {
			slog.Warn("list virtualbox machines failed", "error", lerr)
		}
		if names, lerr := vbox.ListRunningVMs(listCtx, exe); lerr == nil {
			payload.RunningMachines = names
		} else {
			slog.Warn("list running virtualbox machines failed", "error", lerr)
		}
	}

	writeJSON(w, payload)
}
