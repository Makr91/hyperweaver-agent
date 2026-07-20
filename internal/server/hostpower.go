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

type hostStatusUptime struct {
	Seconds   uint64 `json:"seconds"`
	Formatted string `json:"formatted"`
	BootTime  string `json:"boot_time"`
}

type hostStatusMemory struct {
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
	Used  uint64 `json:"used"`
}

type hostStatusResponse struct {
	Hostname    string           `json:"hostname"`
	Uptime      hostStatusUptime `json:"uptime"`
	LoadAverage []float64        `json:"load_average"`
	Memory      hostStatusMemory `json:"memory"`
}

// handleHostStatus mirrors GET /system/host/status (the platform-feasible
// subset: no runlevel, no reboot-required tracking — init concepts absent
// here).
//
//	@Summary		Host system status
//	@Description	Minimum role: viewer. Uptime, load averages, and memory. No runlevel or reboot-required tracking — init concepts absent on this platform trio. 503 when host_power.enabled is false.
//	@Tags			System Host Management
//	@Produce		json
//	@Success		200	{object}	hostStatusResponse	"System status"
//	@Failure		503	"Host power management is disabled in configuration"
//	@Router			/system/host/status [get]
func (s *Server) handleHostStatus(w http.ResponseWriter, _ *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	uptime := hostinfo.UptimeSeconds()
	total, free := hostinfo.MemoryStatus()
	loadavg := hostinfo.LoadAvg()

	writeJSON(w, hostStatusResponse{
		Hostname: hostname,
		Uptime: hostStatusUptime{
			Seconds:   uptime,
			Formatted: formatUptime(uptime),
			BootTime:  bootTime().Format(time.RFC3339),
		},
		LoadAverage: []float64{loadavg[0], loadavg[1], loadavg[2]},
		Memory: hostStatusMemory{
			Total: total,
			Free:  free,
			Used:  total - free,
		},
	})
}

type hostUptimeLoadAverages struct {
	One     float64 `json:"1min"`
	Five    float64 `json:"5min"`
	Fifteen float64 `json:"15min"`
}

type hostUptimeResponse struct {
	UptimeSeconds   uint64                 `json:"uptime_seconds"`
	UptimeFormatted string                 `json:"uptime_formatted"`
	BootTime        string                 `json:"boot_time"`
	LoadAverages    hostUptimeLoadAverages `json:"load_averages"`
}

// handleHostUptime mirrors GET /system/host/uptime.
//
//	@Summary		Host uptime
//	@Description	Minimum role: viewer. 503 when host_power.enabled is false.
//	@Tags			System Host Management
//	@Produce		json
//	@Success		200	{object}	hostUptimeResponse	"Uptime information"
//	@Failure		503	"Host power management is disabled in configuration"
//	@Router			/system/host/uptime [get]
func (s *Server) handleHostUptime(w http.ResponseWriter, _ *http.Request) {
	uptime := hostinfo.UptimeSeconds()
	loadavg := hostinfo.LoadAvg()
	writeJSON(w, hostUptimeResponse{
		UptimeSeconds:   uptime,
		UptimeFormatted: formatUptime(uptime),
		BootTime:        bootTime().Format(time.RFC3339),
		LoadAverages: hostUptimeLoadAverages{
			One:     loadavg[0],
			Five:    loadavg[1],
			Fifteen: loadavg[2],
		},
	})
}

// powerRequest is the shared power-action body.
type powerRequest struct {
	Confirm bool `json:"confirm"`
	// Halt only: emergency acknowledgement (halt skips graceful shutdown entirely)
	Emergency bool `json:"emergency"`
	// Seconds before the action fires (Unix rounds up to minutes)
	GracePeriod *int `json:"grace_period"`
	// Warning broadcast to logged-in users where the platform supports one
	Message string `json:"message"`
}

type powerTaskResponse struct {
	Success     bool      `json:"success"`
	Message     string    `json:"message"`
	TaskID      string    `json:"task_id"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	GracePeriod int       `json:"grace_period"`
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
	if werr := json.NewEncoder(w).Encode(powerTaskResponse{
		Success:     true,
		Message:     label + " task created successfully",
		TaskID:      task.ID,
		Status:      task.Status,
		CreatedAt:   task.CreatedAt,
		GracePeriod: grace,
	}); werr != nil {
		slog.Error("write host power response", "error", werr)
	}
}

// @Summary		Shut down the host
// @Description	Minimum role: admin. Queues a task running the platform shutdown command (Windows shutdown /s, Unix shutdown -h). confirm:true is required. The agent needs the OS privilege the command itself demands — a refusal fails the task honestly. 503 when host_power.enabled is false.
// @Tags			System Host Management
// @Accept			json
// @Produce		json
// @Param			request	body	powerRequest	true	"Power action body (confirm required)"
// @Success		202	{object}	powerTaskResponse	"Shutdown task created"
// @Failure		400	"Missing confirmation or invalid parameters"
// @Failure		503	"Host power management is disabled in configuration"
// @Router			/system/host/shutdown [post]
func (s *Server) handleHostShutdown(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpShutdown, "shutdown", false)
}

// @Summary		Restart the host
// @Description	Minimum role: admin. Same body rules as shutdown. 503 when host_power.enabled is false.
// @Tags			System Host Management
// @Accept			json
// @Produce		json
// @Param			request	body	powerRequest	true	"Power action body (confirm required)"
// @Success		202	"Restart task created"
// @Failure		400	"Missing confirmation or invalid parameters"
// @Failure		503	"Host power management is disabled in configuration"
// @Router			/system/host/restart [post]
func (s *Server) handleHostRestart(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpRestart, "restart", false)
}

// @Summary		Power off the host
// @Description	Minimum role: admin. Manual intervention required to restart the machine. Same body rules as shutdown; Windows makes no shutdown/poweroff distinction. 503 when host_power.enabled is false.
// @Tags			System Host Management
// @Accept			json
// @Produce		json
// @Param			request	body	powerRequest	true	"Power action body (confirm required)"
// @Success		202	"Poweroff task created"
// @Failure		400	"Missing confirmation or invalid parameters"
// @Failure		503	"Host power management is disabled in configuration"
// @Router			/system/host/poweroff [post]
func (s *Server) handleHostPoweroff(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpPoweroff, "poweroff", false)
}

// @Summary		Immediately halt the host
// @Description	Minimum role: admin. No grace period, no graceful shutdown — the emergency stop. Requires BOTH confirm:true and emergency:true. 503 when host_power.enabled is false.
// @Tags			System Host Management
// @Accept			json
// @Produce		json
// @Param			request	body	powerRequest	true	"Power action body (confirm and emergency required)"
// @Success		202	"Halt task created"
// @Failure		400	"Missing confirmation or emergency acknowledgement"
// @Failure		503	"Host power management is disabled in configuration"
// @Router			/system/host/halt [post]
func (s *Server) handleHostHalt(w http.ResponseWriter, r *http.Request) {
	s.queuePowerTask(w, r, hostpower.OpHalt, "halt", true)
}
