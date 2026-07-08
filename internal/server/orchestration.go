package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// Machine orchestration endpoints — the base's ZoneOrchestrationController:
// status, enable/disable (here a config toggle persisted to config.yaml — the
// base's SMF handoff is illumos-only; the agent IS the only lifecycle
// controller on this platform), the priorities listing, and the dry-run test
// plan. Priorities live in settings.boot_priority (Mark's ruling: the faithful
// analog of the base's zonecfg attr) and update DB-immediately via PUT
// /machines/{name} {boot_priority}.

// handleOrchestrationStatus mirrors GET /machines/orchestration/status.
func (s *Server) handleOrchestrationStatus(w http.ResponseWriter, _ *http.Request) {
	controller := "none"
	if s.cfg.Machines.Orchestration.Enabled {
		controller = "hyperweaver-agent"
	}
	writeJSON(w, map[string]any{
		"success":               true,
		"message":               "Machine orchestration status retrieved successfully",
		"orchestration_enabled": s.cfg.Machines.Orchestration.Enabled,
		"controller":            controller,
		"strategy":              s.cfg.Machines.Orchestration.Strategy,
	})
}

// persistOrchestrationEnabled flips the flag live AND on disk (the same
// machines section the config file carries, merged whole).
func (s *Server) persistOrchestrationEnabled(enabled bool) error {
	s.cfg.Machines.Orchestration.Enabled = enabled
	return s.cfg.MergeAndSave(map[string]any{"machines": s.cfg.Machines})
}

// handleOrchestrationEnable mirrors POST /machines/orchestration/enable
// (confirm required — the base's guard).
func (s *Server) handleOrchestrationEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if !body.Confirm {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{
			"success": false,
			"error":   "Confirmation required",
			"details": `You must set "confirm": true to enable machine orchestration`,
		})
		return
	}
	if err := s.persistOrchestrationEnabled(true); err != nil {
		slog.Error("enable orchestration", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to enable machine orchestration")
		return
	}
	enabledBy := auth.FromContext(r.Context()).Name
	slog.Warn("machine orchestration enabled via API", "enabled_by", enabledBy)
	writeJSON(w, map[string]any{
		"success":    true,
		"message":    "Machine orchestration enabled — autostart machines boot in priority order at agent startup",
		"enabled_by": enabledBy,
	})
}

// handleOrchestrationDisable mirrors POST /machines/orchestration/disable.
func (s *Server) handleOrchestrationDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.persistOrchestrationEnabled(false); err != nil {
		slog.Error("disable orchestration", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to disable machine orchestration")
		return
	}
	disabledBy := auth.FromContext(r.Context()).Name
	slog.Info("machine orchestration disabled via API", "disabled_by", disabledBy)
	writeJSON(w, map[string]any{
		"success":     true,
		"message":     "Machine orchestration disabled",
		"disabled_by": disabledBy,
	})
}

// handleMachinePriorities mirrors GET /machines/priorities: every machine
// with its priority, plus the tens-range grouping.
func (s *Server) handleMachinePriorities(w http.ResponseWriter, r *http.Request) {
	entries, err := machines.Prioritized(r.Context(), s.machines)
	if err != nil {
		slog.Error("list machine priorities", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve machine priorities")
		return
	}
	groups := machines.GroupByPriority(entries)
	grouped := map[int][]machines.PriorityEntry{}
	for _, group := range groups {
		grouped[group.PriorityRange] = group.Machines
	}

	list := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		list = append(list, map[string]any{
			"name":                entry.Name,
			"priority":            entry.Priority,
			"state":               entry.State,
			"has_custom_priority": entry.Priority != machines.DefaultPriority,
		})
	}
	writeJSON(w, map[string]any{
		"success":         true,
		"message":         "Machine priorities retrieved successfully",
		"machines":        list,
		"total_machines":  len(list),
		"priority_groups": grouped,
	})
}

// handleOrchestrationTest mirrors POST /machines/orchestration/test: the
// dry-run SHUTDOWN plan (lowest priority first) over running machines —
// nothing executes.
func (s *Server) handleOrchestrationTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Strategy string `json:"strategy"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	strategy := body.Strategy
	if strategy == "" {
		strategy = s.cfg.Machines.Orchestration.Strategy
	}
	switch strategy {
	case "sequential", "parallel_by_priority", "staggered":
	default:
		taskError(w, http.StatusBadRequest,
			"Invalid strategy — valid options: sequential, parallel_by_priority, staggered")
		return
	}

	entries, err := machines.Prioritized(r.Context(), s.machines)
	if err != nil {
		slog.Error("orchestration test", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to test orchestration")
		return
	}
	running := []machines.PriorityEntry{}
	for _, entry := range entries {
		if entry.State == machines.StatusRunning {
			running = append(running, entry)
		}
	}
	if len(running) == 0 {
		writeJSON(w, map[string]any{
			"success":            true,
			"message":            "No running machines found - nothing to orchestrate",
			"execution_plan":     []any{},
			"total_machines":     0,
			"estimated_duration": 0,
		})
		return
	}

	plan := machines.GroupByPriority(running)
	largest := 0
	for _, group := range plan {
		if len(group.Machines) > largest {
			largest = len(group.Machines)
		}
	}
	// The base's estimate: 30s between groups + 120s per machine in the
	// largest group.
	estimated := len(plan)*30 + largest*120

	writeJSON(w, map[string]any{
		"success":            true,
		"message":            "Machine orchestration test completed",
		"execution_plan":     plan,
		"total_machines":     len(running),
		"estimated_duration": estimated,
		"strategy":           strategy,
	})
}
