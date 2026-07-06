package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"os"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/hostpower"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Host power-management endpoints (/system/host/*, the `host-power`
// capability token, config-gated by host_power.enabled — Mark's ruling
// 2026-07-05: remote power control is half the point of a headless
// datacenter host). Mutations are admin-only via the central role policy
// (/system/host is an admin-write prefix) and require confirm:true. Actions
// run as queued tasks through the platform shutdown command.

// disabled503 answers the config-gated-503 convention: a killed surface
// answers 503 on every endpoint, and its capability token is absent from
// GET /api/status — token-gating clients never see these.
func disabled503(w http.ResponseWriter, surface string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error": surface + " is disabled in configuration",
	}); err != nil {
		slog.Error("write disabled response", "error", err)
	}
}

// hostPowerGate wraps a host-power handler with the config kill-switch.
func (s *Server) hostPowerGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.HostPower.Enabled {
			disabled503(w, "Host power management")
			return
		}
		next(w, r)
	}
}

func formatUptime(seconds uint64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
}

// maxUptimeSeconds caps the uint64→Duration conversion provably inside the
// int64 nanosecond range (~292 years — no host is up longer).
const maxUptimeSeconds = uint64(math.MaxInt64 / int64(time.Second))

func bootTime() time.Time {
	seconds := hostinfo.UptimeSeconds()
	if seconds > maxUptimeSeconds {
		seconds = maxUptimeSeconds
	}
	return time.Now().Add(-time.Duration(seconds) * time.Second).UTC()
}

// handleHostStatus mirrors GET /system/host/status (the platform-feasible
// subset: no runlevel, no reboot-required tracking — init concepts absent
// here).
func (s *Server) handleHostStatus(w http.ResponseWriter, _ *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	uptime := hostinfo.UptimeSeconds()
	total, free := hostinfo.MemoryStatus()
	loadavg := hostinfo.LoadAvg()

	writeJSON(w, map[string]any{
		"hostname": hostname,
		"uptime": map[string]any{
			"seconds":   uptime,
			"formatted": formatUptime(uptime),
			"boot_time": bootTime().Format(time.RFC3339),
		},
		"load_average": []float64{loadavg[0], loadavg[1], loadavg[2]},
		"memory": map[string]any{
			"total": total,
			"free":  free,
			"used":  total - free,
		},
	})
}

// handleHostUptime mirrors GET /system/host/uptime.
func (s *Server) handleHostUptime(w http.ResponseWriter, _ *http.Request) {
	uptime := hostinfo.UptimeSeconds()
	loadavg := hostinfo.LoadAvg()
	writeJSON(w, map[string]any{
		"uptime_seconds":   uptime,
		"uptime_formatted": formatUptime(uptime),
		"boot_time":        bootTime().Format(time.RFC3339),
		"load_averages": map[string]any{
			"1min":  loadavg[0],
			"5min":  loadavg[1],
			"15min": loadavg[2],
		},
	})
}

// powerRequest is the shared power-action body.
type powerRequest struct {
	Confirm     bool   `json:"confirm"`
	Emergency   bool   `json:"emergency"`
	GracePeriod *int   `json:"grace_period"`
	Message     string `json:"message"`
}

// queuePowerTask validates the shared body rules and queues the operation.
func (s *Server) queuePowerTask(w http.ResponseWriter, r *http.Request, operation, label string, requireEmergency bool) {
	var body powerRequest
	if err := decodeBody(r, &body); err != nil {
		errorResponse(w, http.StatusBadRequest, "Failed to create "+label+" task", "Invalid JSON body")
		return
	}
	if !body.Confirm {
		errorResponse(w, http.StatusBadRequest, "Failed to create "+label+" task",
			"confirm: true is required — this operation affects the whole host")
		return
	}
	if requireEmergency && !body.Emergency {
		errorResponse(w, http.StatusBadRequest, "Failed to create "+label+" task",
			"emergency: true is required — halt skips graceful shutdown entirely")
		return
	}
	grace := 60
	if body.GracePeriod != nil {
		grace = *body.GracePeriod
	}
	if grace < 0 || grace > 7200 {
		errorResponse(w, http.StatusBadRequest, "Failed to create "+label+" task",
			"grace_period must be between 0 and 7200 seconds")
		return
	}
	if len(body.Message) > 200 {
		errorResponse(w, http.StatusBadRequest, "Failed to create "+label+" task",
			"message must be at most 200 characters")
		return
	}

	// One power action at a time: an existing pending/running task of the
	// same operation is reused instead of double-queued.
	if existing, derr := s.dedupTask(r.Context(), "system", operation); derr == nil && existing != nil {
		successResponse(w, label+" task already queued", map[string]any{
			"task_id": existing.ID,
			"status":  existing.Status,
		})
		return
	}

	metadata, err := hostpower.MetadataJSON(hostpower.Metadata{
		GracePeriod: grace,
		Message:     body.Message,
	})
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, "Failed to create "+label+" task", err.Error())
		return
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   operation,
		Priority:    tasks.PriorityCritical,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue host power task", "operation", operation, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to create "+label+" task", err.Error())
		return
	}
	slog.Warn("host power task queued", "operation", operation,
		"grace_period", grace, "by", auth.FromContext(r.Context()).Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":      true,
		"message":      label + " task created successfully",
		"task_id":      task.ID,
		"status":       task.Status,
		"created_at":   task.CreatedAt,
		"grace_period": grace,
	}); werr != nil {
		slog.Error("write host power response", "error", werr)
	}
}

func (s *Server) handleHostShutdown(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpShutdown, "shutdown", false)
}

func (s *Server) handleHostRestart(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpRestart, "restart", false)
}

func (s *Server) handleHostPoweroff(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpPoweroff, "poweroff", false)
}

func (s *Server) handleHostHalt(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpHalt, "halt", true)
}
