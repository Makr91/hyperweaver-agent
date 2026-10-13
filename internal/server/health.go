package server

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/ansiblehost"
	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
)

const (
	healthOK      = "ok"
	healthWarning = "warning"
	healthError   = "error"

	healthProbeTimeout = 15 * time.Second

	noteVirtualBoxWSL = "virtualbox_wsl"
	noteRsyncOld      = "rsync_old"

	textVirtualBoxWSL = "WSL and VirtualBox share this host's virtualization; VirtualBox machines may be unstable while WSL runs."
	textRsyncOld      = "File synchronization requires rsync version higher than 2.6.9. Please upgrade rsync using MacPorts or Homebrew package managers. Alternatively, you can use the SCP plugin, though it may result in slower transfer speeds compared to rsync."
)

// healthNote is one caution of the host, drawn in the heart's popover.
type healthNote struct {
	Code  string `json:"code"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

type healthReport struct {
	// ok | warning | error — the worst of the services
	Status string `json:"status" example:"ok"`
	// When the report was taken, RFC 3339
	Timestamp string `json:"timestamp"`
	// One coarse status word per service: database, hypervisor, tasks, monitoring
	Services map[string]string `json:"services"`
	// The detected tools with their versions, the rows GET /api/version answers
	Tools []prereqs.Tool `json:"tools"`
	// The host as GET /api/version answers it
	Host hostinfo.Info `json:"host"`
	// The cautions of the host, empty while it has nothing to say
	Notes []healthNote `json:"notes"`
}

type healthState struct {
	mu   sync.Mutex
	last *healthReport
}

func (s *Server) databaseHealth(ctx context.Context) string {
	for i := range s.dbs {
		if err := s.dbs[i].DB.PingContext(ctx); err != nil {
			return healthError
		}
	}
	return healthOK
}

// hypervisorHealth answers the hypervisor's state and, on a Windows host where VirtualBox and a WSL distribution share the virtualization, the warning that names it.
func (s *Server) hypervisorHealth(ctx context.Context) (string, []healthNote) {
	if machines.VBoxManagePath(ctx) == "" && !utmHypervisorAvailable(ctx) {
		return healthError, nil
	}
	if runtime.GOOS == "windows" && machines.VBoxManagePath(ctx) != "" {
		if installed, _, _ := ansiblehost.DetectWSL(ctx); installed {
			return healthWarning, []healthNote{{Code: noteVirtualBoxWSL, Level: healthWarning, Text: textVirtualBoxWSL}}
		}
	}
	return healthOK, nil
}

func (s *Server) taskHealth() string {
	if s.tasks.ProcessorRunning() {
		return healthOK
	}
	return healthError
}

func (s *Server) monitoringHealth() string {
	if s.monitor.StorageEnabled() && !s.monitor.Running() {
		return healthError
	}
	if _, failed := s.monitor.Stats()["last_error"]; failed {
		return healthWarning
	}
	return healthOK
}

// rsyncNote answers the old-rsync caution on a non-Windows host whose rsync is 2.6.9 or older.
func rsyncNote(tools []prereqs.Tool) []healthNote {
	if runtime.GOOS == "windows" {
		return nil
	}
	for _, tool := range tools {
		if tool.Name == "rsync" && tool.Installed && tool.Version != "" && versionAtMost(tool.Version, 2, 6, 9) {
			return []healthNote{{Code: noteRsyncOld, Level: healthWarning, Text: textRsyncOld}}
		}
	}
	return nil
}

// versionAtMost reports whether a dotted version is at or below major.minor.patch.
func versionAtMost(version string, major, minor, patch int) bool {
	bounds := []int{major, minor, patch}
	parts := strings.Split(version, ".")
	for i := range bounds {
		value := 0
		if i < len(parts) {
			digits := strings.TrimRightFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' })
			value, _ = strconv.Atoi(digits)
		}
		if value < bounds[i] {
			return true
		}
		if value > bounds[i] {
			return false
		}
	}
	return true
}

func worstHealth(services map[string]string) string {
	worst := healthOK
	for _, state := range services {
		if state == healthError {
			return healthError
		}
		if state == healthWarning {
			worst = healthWarning
		}
	}
	return worst
}

func (s *Server) healthReport(ctx context.Context) *healthReport {
	probeCtx, cancel := context.WithTimeout(ctx, healthProbeTimeout)
	defer cancel()
	tools := prereqs.Detect(probeCtx)
	hypervisor, notes := s.hypervisorHealth(probeCtx)
	notes = append(notes, rsyncNote(tools)...)
	if notes == nil {
		notes = []healthNote{}
	}
	services := map[string]string{
		"database":   s.databaseHealth(probeCtx),
		"hypervisor": hypervisor,
		"tasks":      s.taskHealth(),
		"monitoring": s.monitoringHealth(),
	}
	return &healthReport{
		Status:    worstHealth(services),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services:  services,
		Tools:     tools,
		Host:      hostinfo.Get(),
		Notes:     notes,
	}
}

func healthChanged(previous, next *healthReport) bool {
	if previous == nil || previous.Status != next.Status || len(previous.Services) != len(next.Services) ||
		len(previous.Notes) != len(next.Notes) || len(previous.Tools) != len(next.Tools) {
		return true
	}
	for service, state := range next.Services {
		if previous.Services[service] != state {
			return true
		}
	}
	for i := range next.Notes {
		if previous.Notes[i] != next.Notes[i] {
			return true
		}
	}
	for i := range next.Tools {
		if previous.Tools[i].Name != next.Tools[i].Name || previous.Tools[i].Installed != next.Tools[i].Installed ||
			previous.Tools[i].Version != next.Tools[i].Version {
			return true
		}
	}
	return false
}

func (s *Server) publishHealth() {
	go func() {
		report := s.healthReport(context.Background())
		s.health.mu.Lock()
		changed := healthChanged(s.health.last, report)
		if changed {
			s.health.last = report
		}
		s.health.mu.Unlock()
		if changed {
			s.events.publish("health", "health", report)
		}
	}()
}

// @Summary		Health of the agent and its services
// @Description	Public. The one health shape every UI backend answers: status is ok, warning or error, the worst of the services; timestamp is when the report was taken; services carries one coarse status word each for database (every open database file answers a ping), hypervisor (VBoxManage or a usable UTM is present; warning on a Windows host where a WSL distribution runs beside VirtualBox), tasks (the task processor runs) and monitoring (error when storage is on and the collector is down, warning after a collector error). tools lists the detected tools as GET /api/version does, each {name, installed, version}, version left out while unknown; host is the host as GET /api/version answers it; notes lists the cautions of the host as {code, level, text}, level warning or error: virtualbox_wsl on a Windows host running WSL beside VirtualBox, rsync_old on a non-Windows host whose rsync is 2.6.9 or older; empty while there is nothing to say. The same report is sent as the health event on the health topic of GET /api/events whenever a task ends and the report differs from the last one sent.
// @Tags			Status
// @Produce		json
// @Success		200	{object}	healthReport	"The health report"
// @Router			/api/health [get]
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.healthReport(r.Context()))
}
