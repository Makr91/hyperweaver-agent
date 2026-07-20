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

type orchestrationStatusResponse struct {
	Controller           string `json:"controller"`
	Message              string `json:"message"`
	OrchestrationEnabled bool   `json:"orchestration_enabled"`
	Strategy             string `json:"strategy"`
	Success              bool   `json:"success"`
}

// handleOrchestrationStatus mirrors GET /machines/orchestration/status.
//
//	@Summary		Orchestration status
//	@Description	Minimum role: viewer. Whether ordered startup/shutdown is enabled (machines.orchestration.enabled) and the configured strategy. The base's SMF-controller handoff is illumos-only — this agent is the only lifecycle controller on its platform, so controller is hyperweaver-agent or none.
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	orchestrationStatusResponse	"Orchestration status"
//	@Router			/machines/orchestration/status [get]
func (s *Server) handleOrchestrationStatus(w http.ResponseWriter, _ *http.Request) {
	controller := "none"
	if s.cfg.Machines.Orchestration.Enabled {
		controller = "hyperweaver-agent"
	}
	writeJSON(w, orchestrationStatusResponse{
		Controller:           controller,
		Message:              "Machine orchestration status retrieved successfully",
		OrchestrationEnabled: s.cfg.Machines.Orchestration.Enabled,
		Strategy:             s.cfg.Machines.Orchestration.Strategy,
		Success:              true,
	})
}

// persistOrchestrationEnabled flips the flag live AND on disk (the same
// machines section the config file carries, merged whole).
func (s *Server) persistOrchestrationEnabled(enabled bool) error {
	s.cfg.Machines.Orchestration.Enabled = enabled
	return s.cfg.MergeAndSave(map[string]any{"machines": s.cfg.Machines})
}

type orchestrationEnableRequest struct {
	Confirm bool `json:"confirm"`
}

type orchestrationEnableResponse struct {
	EnabledBy string `json:"enabled_by"`
	Message   string `json:"message"`
	Success   bool   `json:"success"`
}

// handleOrchestrationEnable mirrors POST /machines/orchestration/enable
// (confirm required — the base's guard).
//
//	@Summary		Enable machine orchestration
//	@Description	Minimum role: operator. Requires {"confirm": true}. Persists machines.orchestration.enabled to config.yaml and applies live: on the NEXT agent startup, autostart machines (vbox.autostart.enabled in the spec) boot in settings.boot_priority order, highest first; agent exit with keep_running_on_exit false stops machines lowest-first.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body		orchestrationEnableRequest	true	"Requires confirm: true"
//	@Success		200		{object}	orchestrationEnableResponse	"Orchestration enabled"
//	@Failure		400		{object}	map[string]string			"Missing confirmation"
//	@Router			/machines/orchestration/enable [post]
func (s *Server) handleOrchestrationEnable(w http.ResponseWriter, r *http.Request) {
	var body orchestrationEnableRequest
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
	writeJSON(w, orchestrationEnableResponse{
		EnabledBy: enabledBy,
		Message:   "Machine orchestration enabled — autostart machines boot in priority order at agent startup",
		Success:   true,
	})
}

type orchestrationDisableResponse struct {
	DisabledBy string `json:"disabled_by"`
	Message    string `json:"message"`
	Success    bool   `json:"success"`
}

// handleOrchestrationDisable mirrors POST /machines/orchestration/disable.
//
//	@Summary		Disable machine orchestration
//	@Description	Minimum role: operator. Persists machines.orchestration.enabled: false.
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	orchestrationDisableResponse	"Orchestration disabled"
//	@Router			/machines/orchestration/disable [post]
func (s *Server) handleOrchestrationDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.persistOrchestrationEnabled(false); err != nil {
		slog.Error("disable orchestration", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to disable machine orchestration")
		return
	}
	disabledBy := auth.FromContext(r.Context()).Name
	slog.Info("machine orchestration disabled via API", "disabled_by", disabledBy)
	writeJSON(w, orchestrationDisableResponse{
		DisabledBy: disabledBy,
		Message:    "Machine orchestration disabled",
		Success:    true,
	})
}

type machinePriorityEntry struct {
	HasCustomPriority bool   `json:"has_custom_priority"`
	Name              string `json:"name"`
	Priority          int    `json:"priority"`
	State             string `json:"state"`
}

type machinePrioritiesResponse struct {
	Machines       []machinePriorityEntry           `json:"machines"`
	Message        string                           `json:"message"`
	PriorityGroups map[int][]machines.PriorityEntry `json:"priority_groups"`
	Success        bool                             `json:"success"`
	TotalMachines  int                              `json:"total_machines"`
}

// handleMachinePriorities mirrors GET /machines/priorities: every machine
// with its priority, plus the tens-range grouping.
//
//	@Summary		Machine boot priorities
//	@Description	Minimum role: viewer. Every machine with its boot priority (settings.boot_priority, 1-100, default 95 — set via PUT /machines/{name} {boot_priority}, DB-immediate) plus the tens-range grouping.
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	machinePrioritiesResponse	"Priorities"
//	@Router			/machines/priorities [get]
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

	list := make([]machinePriorityEntry, 0, len(entries))
	for _, entry := range entries {
		list = append(list, machinePriorityEntry{
			HasCustomPriority: entry.Priority != machines.DefaultPriority,
			Name:              entry.Name,
			Priority:          entry.Priority,
			State:             entry.State,
		})
	}
	writeJSON(w, machinePrioritiesResponse{
		Machines:       list,
		Message:        "Machine priorities retrieved successfully",
		PriorityGroups: grouped,
		Success:        true,
		TotalMachines:  len(list),
	})
}

type orchestrationTestRequest struct {
	Strategy string `json:"strategy" enums:"sequential,parallel_by_priority,staggered"`
}

type orchestrationTestResponse struct {
	EstimatedDuration int                      `json:"estimated_duration"`
	ExecutionPlan     []machines.PriorityGroup `json:"execution_plan"`
	Message           string                   `json:"message"`
	Strategy          string                   `json:"strategy,omitempty"`
	Success           bool                     `json:"success"`
	TotalMachines     int                      `json:"total_machines"`
}

// handleOrchestrationTest mirrors POST /machines/orchestration/test: the
// dry-run SHUTDOWN plan (lowest priority first) over running machines —
// nothing executes.
//
//	@Summary		Test orchestration (dry run)
//	@Description	Minimum role: operator. Computes the SHUTDOWN execution plan over running machines — priority groups of ten, lowest first — without executing anything, plus a duration estimate (30s between groups + 120s per machine in the largest group, the base's arithmetic).
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body		orchestrationTestRequest	false	"Optional shutdown strategy selector"
//	@Success		200		{object}	orchestrationTestResponse	"Execution plan"
//	@Failure		400		{object}	map[string]string			"Invalid strategy"
//	@Router			/machines/orchestration/test [post]
func (s *Server) handleOrchestrationTest(w http.ResponseWriter, r *http.Request) {
	var body orchestrationTestRequest
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
		writeJSON(w, orchestrationTestResponse{
			EstimatedDuration: 0,
			ExecutionPlan:     []machines.PriorityGroup{},
			Message:           "No running machines found - nothing to orchestrate",
			Success:           true,
			TotalMachines:     0,
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

	writeJSON(w, orchestrationTestResponse{
		EstimatedDuration: estimated,
		ExecutionPlan:     plan,
		Message:           "Machine orchestration test completed",
		Strategy:          strategy,
		Success:           true,
		TotalMachines:     len(running),
	})
}
