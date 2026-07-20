package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine endpoints (Agent API v1 machines surface, /machines/* — the only
// machine path, per Mark's 2026-07-05 ruling in hyperweaver-ai-sync.md, with
// the de-zoned wire vocabulary agreed there). Lifecycle operations are
// task-queued, idempotency-checked, and dedup-checked exactly like the Node
// agent's power controller.

// machineNamePattern accepts VirtualBox-legal machine names (user-chosen per
// design D-G — no FQDN requirement), rejecting path- and shell-hostile input.
var machineNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,254}$`)

func validMachineName(name string) bool {
	return machineNamePattern.MatchString(name)
}

// liveMachineStatus asks the machine's hypervisor for its current state —
// the pre-operation idempotency check ("not_found" when no VM exists,
// matching the Node agent's getSystemZoneStatus contract). The UUID
// addresses the VM once known — a provisioned machine's VirtualBox name is
// Hosts.rb's own; utmctl takes the same UUID-else-name target.
func liveMachineStatus(ctx context.Context, machine *machines.Machine) string {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if machine.Hypervisor == machines.HypervisorUTM {
		exe := machines.UTMCtlPath(ctx)
		if exe == "" {
			return "not_found"
		}
		status, err := utm.Status(probeCtx, exe, machine.VBoxTarget())
		if err != nil {
			return "not_found"
		}
		return utm.MapUTMState(status)
	}
	exe := machines.VBoxManagePath(ctx)
	if exe == "" {
		return "not_found"
	}
	info, err := vbox.ShowVMInfo(probeCtx, exe, machine.VBoxTarget())
	if err != nil {
		return "not_found"
	}
	return machines.MapVBoxState(info.State)
}

// findMachine loads a machine or writes the 400/404 the Node agent would.
func (s *Server) findMachine(w http.ResponseWriter, r *http.Request) *machines.Machine {
	name := r.PathValue("machineName")
	if !validMachineName(name) {
		taskError(w, http.StatusBadRequest, "Invalid machine name")
		return nil
	}
	machine, err := s.machines.Get(r.Context(), name)
	if errors.Is(err, machines.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Machine not found")
		return nil
	}
	if err != nil {
		slog.Error("load machine", "machine", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve machine")
		return nil
	}
	return machine
}

// machineListResponse is GET /machines' answer: the filtered rows and their
// total count.
type machineListResponse struct {
	Machines []*machines.Machine `json:"machines"`
	Total    int                 `json:"total"`
}

// handleListMachines: status/orphaned filters, post-filter on tag,
// name-ascending.
//
//	@Summary		List machines
//	@Description	Minimum role: viewer. Machines built outside the agent appear here once the reconciliation sweep imports them.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			tag	query	string	false	"Only machines carrying this tag"
//	@Success		200	{object}	machineListResponse	"Machines retrieved"
//	@Router			/machines [get]
func (s *Server) handleListMachines(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := machines.ListFilter{Status: query.Get("status")}
	if raw := query.Get("orphaned"); raw != "" {
		orphaned := raw == "true"
		filter.Orphaned = &orphaned
	}

	list, err := s.machines.List(r.Context(), &filter)
	if err != nil {
		slog.Error("list machines", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve machines")
		return
	}

	if tag := query.Get("tag"); tag != "" {
		filtered := []*machines.Machine{}
		for _, m := range list {
			var machineTags []string
			if m.Tags != nil {
				if uerr := json.Unmarshal(m.Tags, &machineTags); uerr != nil {
					continue
				}
			}
			for _, t := range machineTags {
				if t == tag {
					filtered = append(filtered, m)
					break
				}
			}
		}
		list = filtered
	}

	writeJSON(w, machineListResponse{Machines: list, Total: len(list)})
}

// handleMachineDetails: live status check (updating the registry when it
// drifted), the machine record, its live configuration, and its pending
// tasks.
//
//	@Summary		Machine details
//	@Description	Minimum role: viewer. Live-checks VirtualBox (updating the registry on drift) and returns the record, its live configuration, pending tasks, and knob_current — the current values in PUT's own vocabulary (the Edit-surface prefill).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Machine details"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName} [get]
func (s *Server) handleMachineDetails(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}

	// One showvminfo serves the status probe AND knob_current's reverse map
	// (liveMachineStatus would discard the view). The showvminfo enrichment
	// is VBox plumbing — utm machines take the plain status probe and live
	// stays nil (knob_current and the settings file answer honestly absent).
	var live *vbox.Info
	exe := machines.VBoxManagePath(r.Context())
	systemStatus := "not_found"
	if machine.Hypervisor == machines.HypervisorUTM {
		systemStatus = liveMachineStatus(r.Context(), machine)
	} else if exe != "" {
		probeCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		if info, err := vbox.ShowVMInfo(probeCtx, exe, machine.VBoxTarget()); err == nil {
			live = info
			systemStatus = machines.MapVBoxState(info.State)
		}
		cancel()
	}
	if systemStatus == "not_found" {
		// Created-but-never-started machines (configured, no UUID) have no
		// VM by design; report their stored status.
		if machine.UUID == nil {
			systemStatus = machine.Status
		}
		if machine.UUID != nil && !machine.IsOrphaned {
			if err := s.machines.SetOrphaned(r.Context(), machine.Name, true); err != nil {
				slog.Error("mark machine orphaned", "machine", machine.Name, "error", err)
			}
		}
	} else if systemStatus != machine.Status {
		if err := s.machines.SetStatus(r.Context(), machine.Name, systemStatus); err != nil {
			slog.Error("update machine status", "machine", machine.Name, "error", err)
		}
	}

	fresh, err := s.machines.Get(r.Context(), machine.Name)
	if err != nil {
		slog.Error("reload machine", "machine", machine.Name, "error", err)
		fresh = machine
	}

	active := []*tasks.Task{}
	for _, status := range []string{tasks.StatusPending, tasks.StatusRunning} {
		filter := tasks.ListFilter{MachineName: machine.Name, Status: status, Limit: 10}
		list, lerr := s.tasks.Store().List(r.Context(), &filter)
		if lerr != nil {
			slog.Warn("list machine tasks", "machine", machine.Name, "error", lerr)
			continue
		}
		active = append(active, list...)
	}

	var configuration json.RawMessage
	if fresh.Configuration != nil {
		configuration = fresh.Configuration
	} else {
		configuration = json.RawMessage("{}")
	}

	// The post-provision welcome page (SHI's web address), read live from
	// the working copy's results.yml/.vagrant/done.txt — null until the
	// first successful provision writes it.
	var webAddress any
	if fresh.Provisioned() {
		if url := machines.WelcomeURL(*fresh.Home); url != "" {
			webAddress = url
		}
	}

	// knob_current: the current values in PUT's own vocabulary (the Edit
	// surface's prefill). showvminfo's ostype is the DESCRIPTION; the ID PUT
	// takes resolves through this build's own ostypes feed.
	osTypeID := ""
	if live != nil && live.OSType != "" {
		if types, terr := vbox.ListOSTypes(r.Context(), exe); terr == nil {
			for _, t := range types {
				if t.Description == live.OSType {
					osTypeID = t.ID
					break
				}
			}
		}
	}
	// The accrued pending set (the accrue-changes contract) — null when none.
	var pendingChanges any
	if pending := machines.ParseConfiguration(fresh).Section("pending_changes"); len(pending) > 0 {
		pendingChanges = pending
	}

	var liveRaw map[string]string
	var settingsFile *vbox.MachineSettings
	if live != nil {
		liveRaw = live.Raw
		// The .vbox settings fill the knobs showvminfo never emits; a failed
		// read just leaves them absent (unknowable stays honest).
		if live.ConfigFile != "" {
			if ms, merr := vbox.ReadMachineSettings(live.ConfigFile); merr == nil {
				settingsFile = ms
			} else {
				slog.Debug("read machine settings file", "machine", machine.Name, "error", merr)
			}
		}
	}

	writeJSON(w, map[string]any{
		"machine_info":       fresh,
		"configuration":      configuration,
		"active_vnc_session": nil,
		"pending_tasks":      active,
		"system_status":      systemStatus,
		"web_address":        webAddress,
		"knob_current":       machines.KnobCurrent(fresh, liveRaw, osTypeID, settingsFile),
		"pending_changes":    pendingChanges,
	})
}

// dedupTask returns an already pending/running task of the same operation for
// the machine, so double-clicks reuse it instead of double-queueing (Node
// agent behavior).
func (s *Server) dedupTask(ctx context.Context, machineName, operation string) (*tasks.Task, error) {
	filter := tasks.ListFilter{MachineName: machineName, Operation: operation, Limit: 20}
	list, err := s.tasks.Store().List(ctx, &filter)
	if err != nil {
		return nil, err
	}
	for _, t := range list {
		if t.Status == tasks.StatusPending || t.Status == tasks.StatusRunning {
			return t, nil
		}
	}
	return nil, nil
}

// operationResponse is the queued-operation answer shape.
func operationResponse(w http.ResponseWriter, taskID any, machineName, operation, status, message string) {
	payload := queuedOperation{
		Success:     true,
		MachineName: machineName,
		Operation:   operation,
		Status:      status,
		Message:     message,
	}
	if id, ok := taskID.(string); ok {
		payload.TaskID = id
	}
	writeJSON(w, payload)
}

// queuePendingApply chains a machine_modify task carrying the machine's
// accrued pending changes (the accrue-changes contract's apply half). The
// _apply_pending marker makes the executor clear them on success; a failed
// apply keeps them pending. Nil when nothing is pending or queueing failed
// (a queue failure never blocks the power operation itself).
func (s *Server) queuePendingApply(ctx context.Context, machine *machines.Machine,
	dependsOn *string, createdBy string,
) *tasks.Task {
	pending := machines.ParseConfiguration(machine).Section("pending_changes")
	if len(pending) == 0 {
		return nil
	}
	pending["_apply_pending"] = true
	raw, err := json.Marshal(pending)
	if err != nil {
		slog.Error("serialize pending changes", "machine", machine.Name, "error", err)
		return nil
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(ctx, &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpModify,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		DependsOn:   dependsOn,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue pending-changes apply", "machine", machine.Name, "error", err)
		return nil
	}
	slog.Info("pending changes apply queued", "machine", machine.Name, "task_id", task.ID)
	return task
}

// queueMachineOp queues one deduped machine operation — the shared shape the
// reset/pause/resume and snapshot handlers ride (start/stop/suspend keep
// their bespoke idempotency answers).
func (s *Server) queueMachineOp(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, operation string, priority int, metadata *string, message string,
) {
	// Dedup applies to bare verbs only — metadata-carrying operations (two
	// different snapshot names) are distinct work, never a double-click.
	if metadata == nil {
		if existing, err := s.dedupTask(r.Context(), machine.Name, operation); err != nil {
			slog.Error("check existing task", "machine", machine.Name, "operation", operation, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to queue "+operation+" task")
			return
		} else if existing != nil {
			operationResponse(w, existing.ID, machine.Name, operation, existing.Status,
				operation+" task already queued")
			return
		}
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   operation,
		Priority:    priority,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue machine task", "machine", machine.Name, "operation", operation, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue "+operation+" task")
		return
	}
	operationResponse(w, task.ID, machine.Name, operation, tasks.StatusPending, message)
}
