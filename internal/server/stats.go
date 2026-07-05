package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// statsPayload mirrors the Node agent's GET /stats document (the shared v1
// stats shape): host-OS numbers in Node's os-module vocabulary plus machine
// name lists. The `zones` field names are the contract's — kept verbatim for
// wire parity even though this agent's machines are VirtualBox VMs. The Node
// payload's cpus array is deliberately absent: no UI consumer reads it; add
// it when one does.
type statsPayload struct {
	Hostname     string     `json:"hostname"`
	EOL          string     `json:"eol"`
	Arch         string     `json:"arch"`
	Endianness   string     `json:"endianness"`
	Freemem      uint64     `json:"freemem"`
	Loadavg      [3]float64 `json:"loadavg"`
	Platform     string     `json:"platform"`
	Release      string     `json:"release"`
	Totalmem     uint64     `json:"totalmem"`
	Type         string     `json:"type"`
	Uptime       uint64     `json:"uptime"`
	Version      string     `json:"version"`
	Allzones     []string   `json:"allzones"`
	Runningzones []string   `json:"runningzones"`
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
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	total, free := hostinfo.MemoryStatus()

	payload := statsPayload{
		Hostname:     hostname,
		EOL:          eolString(),
		Arch:         nodeArch(),
		Endianness:   "LE",
		Freemem:      free,
		Loadavg:      hostinfo.LoadAvg(),
		Platform:     nodePlatform(),
		Release:      hostinfo.KernelRelease(),
		Totalmem:     total,
		Type:         hostinfo.Type(),
		Uptime:       hostinfo.UptimeSeconds(),
		Version:      hostinfo.Get().OS,
		Allzones:     []string{},
		Runningzones: []string{},
	}

	if exe := vboxManagePath(r.Context()); exe != "" {
		listCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if names, lerr := vbox.ListVMs(listCtx, exe); lerr == nil {
			payload.Allzones = names
		} else {
			slog.Warn("list virtualbox machines failed", "error", lerr)
		}
		if names, lerr := vbox.ListRunningVMs(listCtx, exe); lerr == nil {
			payload.Runningzones = names
		} else {
			slog.Warn("list running virtualbox machines failed", "error", lerr)
		}
	}

	writeJSON(w, payload)
}
