package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// handleMachineConfig: the live configuration document (VirtualBox's
// machinereadable view on this agent).
//
//	@Summary		Machine configuration
//	@Description	Minimum role: viewer. The live configuration document (VBoxManage showvminfo --machinereadable view on this agent), falling back to the last reconciled copy.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Machine configuration"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/config [get]
func (s *Server) handleMachineConfig(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}

	exe := machines.VBoxManagePath(r.Context())
	if exe != "" {
		if info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget()); err == nil {
			writeJSON(w, map[string]any{
				"machine_name":  machine.Name,
				"configuration": info.Raw,
			})
			return
		}
	}

	var configuration json.RawMessage
	if machine.Configuration != nil {
		configuration = machine.Configuration
	} else {
		configuration = json.RawMessage("{}")
	}
	writeJSON(w, map[string]any{
		"machine_name":  machine.Name,
		"configuration": configuration,
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

// handleStartMachine queues a start task — one native VBoxManage boot for
// every machine (the provision pipeline queues this same operation as its
// boot child).
//
//	@Summary		Start a machine
//	@Description	Minimum role: operator. One native start task for EVERY machine (VBoxManage startvm --type headless) — the provision pipeline queues this same operation as its boot child. Idempotent: already-running machines answer already_running; an existing pending/running start task is reused. Accrued pending changes (the accrue-changes contract) apply FIRST — a machine_modify task is chained ahead and the start DEPENDS on it, so a bad pending value fails the boot honestly (clear via DELETE /machines/{name}/pending-changes or re-PUT the value). With machines.provision_on_start enabled, a machine's VERY FIRST start (stored provisioner document, never provisioned) queues the full provision pipeline instead — the answer carries operation machine_provision_orchestration and the parent task id; later starts, restarts, and document-less machines always boot plainly.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Start task queued (or machine already running)"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/start [post]
func (s *Server) handleStartMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}

	if liveMachineStatus(r.Context(), machine) == machines.StatusRunning {
		operationResponse(w, nil, machine.Name, machines.OpStart, "already_running",
			"Machine is already running")
		return
	}

	if existing, err := s.dedupTask(r.Context(), machine.Name, machines.OpStart); err != nil {
		slog.Error("check existing start task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue start task")
		return
	} else if existing != nil {
		operationResponse(w, existing.ID, machine.Name, machines.OpStart, existing.Status,
			"Start task already queued")
		return
	}

	// machines.provision_on_start: a never-provisioned machine with a stored
	// document boots THROUGH the provision pipeline on its first start
	// (SHI's provisionserversonstart; the chain includes the boot child).
	if parentID, ok := s.provisionOnStartPipeline(r.Context(), machine,
		auth.FromContext(r.Context()).Name); ok {
		operationResponse(w, parentID, machine.Name, machines.OpProvisionOrchestration,
			tasks.StatusPending,
			"First start queued with provisioning (machines.provision_on_start)")
		return
	}

	// Accrued pending changes apply FIRST (modify → start chain) — the safety
	// net for machines powered off outside the agent. Start depends on the
	// modify: a bad pending value fails the boot honestly instead of booting
	// and pretending the changes applied.
	createdBy := auth.FromContext(r.Context()).Name
	var dependsOn *string
	message := "Start task queued successfully"
	if applyTask := s.queuePendingApply(r.Context(), machine, nil, createdBy); applyTask != nil {
		dependsOn = &applyTask.ID
		message = "Pending changes apply queued, start chained after it"
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStart,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		DependsOn:   dependsOn,
	})
	if err != nil {
		slog.Error("queue start task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue start task")
		return
	}
	operationResponse(w, task.ID, machine.Name, machines.OpStart, tasks.StatusPending, message)
}

// cancelPendingStarts cancels pending start tasks before a stop (Node agent
// behavior: a stop overrides a queued start).
func (s *Server) cancelPendingStarts(ctx context.Context, machineName string) {
	filter := tasks.ListFilter{
		MachineName: machineName,
		Operation:   machines.OpStart,
		Status:      tasks.StatusPending,
		Limit:       50,
	}
	list, err := s.tasks.Store().List(ctx, &filter)
	if err != nil {
		slog.Warn("list pending start tasks", "machine", machineName, "error", err)
		return
	}
	for _, t := range list {
		if _, cerr := s.tasks.Cancel(ctx, t.ID); cerr != nil {
			slog.Warn("cancel pending start task", "task_id", t.ID, "error", cerr)
		}
	}
}

// handleStopMachine queues a stop task (?force=true powers off hard).
//
//	@Summary		Stop a machine
//	@Description	Minimum role: operator. Queues a stop task and cancels pending starts. The graceful ladder (Mark's ruling 2026-07-12): QEMU guest-agent shutdown first (the guest OS acting on itself — honored even by a locked Windows console that ignores ACPI; channels with no qemu-ga fall through in <5s) → ACPI power button → hard poweroff when the guest ignores both (each graceful rung waits machines.shutdown_timeout once, never twice). force=true goes straight to poweroff. Accrued pending changes (the accrue-changes contract) apply right after the power-off via a chained machine_modify task.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Stop task queued (or machine already stopped)"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/stop [post]
func (s *Server) handleStopMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	force := r.URL.Query().Get("force") == "true"

	status := liveMachineStatus(r.Context(), machine)
	if status == machines.StatusStopped || status == machines.StatusConfigured || status == "not_found" {
		operationResponse(w, nil, machine.Name, machines.OpStop, "already_stopped",
			"Machine is already stopped")
		return
	}

	s.cancelPendingStarts(r.Context(), machine.Name)

	if existing, err := s.dedupTask(r.Context(), machine.Name, machines.OpStop); err != nil {
		slog.Error("check existing stop task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue stop task")
		return
	} else if existing != nil {
		operationResponse(w, existing.ID, machine.Name, machines.OpStop, existing.Status,
			"Stop task already queued")
		return
	}

	metadata, err := stopMetadataJSON(force)
	if err != nil {
		slog.Error("serialize stop metadata", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue stop task")
		return
	}
	createdBy := auth.FromContext(r.Context()).Name
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStop,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   createdBy,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue stop task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue stop task")
		return
	}
	// Accrued pending changes apply right after the power-off.
	message := "Stop task queued successfully"
	if s.queuePendingApply(r.Context(), machine, &task.ID, createdBy) != nil {
		message = "Stop task queued, pending changes apply chained after it"
	}
	operationResponse(w, task.ID, machine.Name, machines.OpStop, tasks.StatusPending, message)
}

func stopMetadataJSON(force bool) (*string, error) {
	raw, err := json.Marshal(map[string]bool{"force": force})
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// handleRestartMachine queues a HIGH-priority stop and a MEDIUM-priority
// start chained on it.
//
//	@Summary		Restart a machine
//	@Description	Minimum role: operator. Queues a HIGH-priority stop and a MEDIUM-priority start chained on it. Accrued pending changes (the accrue-changes contract) slot between the two — the power cycle that applies them.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Restart tasks queued"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/restart [post]
func (s *Server) handleRestartMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	createdBy := auth.FromContext(r.Context()).Name

	metadata, err := stopMetadataJSON(false)
	if err != nil {
		slog.Error("serialize stop metadata", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue restart tasks")
		return
	}
	stopTask, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStop,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   createdBy,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue restart stop task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue restart tasks")
		return
	}
	// Accrued pending changes slot between stop and start.
	startDependsOn := &stopTask.ID
	if applyTask := s.queuePendingApply(r.Context(), machine, &stopTask.ID, createdBy); applyTask != nil {
		startDependsOn = &applyTask.ID
	}
	startTask, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStart,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		DependsOn:   startDependsOn,
	})
	if err != nil {
		slog.Error("queue restart start task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue restart tasks")
		return
	}

	writeJSON(w, map[string]any{
		"success": true,
		"restart_tasks": map[string]any{
			"stop_task_id":  stopTask.ID,
			"start_task_id": startTask.ID,
		},
		"machine_name": machine.Name,
		"operation":    "restart",
		"status":       tasks.StatusPending,
		"message":      "Restart tasks queued successfully",
	})
}

// handleSuspendMachine queues a suspend (vagrant suspend / savestate) — SHI
// parity; the Node agent has no zone analog.
//
//	@Summary		Suspend a machine
//	@Description	Minimum role: operator. Saves the machine's state (VBoxManage controlvm savestate). Advertised by the machine-suspend capability token — the UI shows Suspend only on agents that carry it.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Suspend task queued"
//	@Failure		400	"Machine is not running"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/suspend [post]
func (s *Server) handleSuspendMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}

	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Can only suspend a running machine")
		return
	}

	if existing, err := s.dedupTask(r.Context(), machine.Name, machines.OpSuspend); err != nil {
		slog.Error("check existing suspend task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue suspend task")
		return
	} else if existing != nil {
		operationResponse(w, existing.ID, machine.Name, machines.OpSuspend, existing.Status,
			"Suspend task already queued")
		return
	}

	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpSuspend,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   auth.FromContext(r.Context()).Name,
	})
	if err != nil {
		slog.Error("queue suspend task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue suspend task")
		return
	}
	operationResponse(w, task.ID, machine.Name, machines.OpSuspend, tasks.StatusPending,
		"Suspend task queued successfully")
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

// handleResetMachine queues a hard reset (`controlvm reset` — the reboot
// VirtualBox offers beyond the stop→start chain).
//
//	@Summary		Hard-reset a machine
//	@Description	Minimum role: operator. VBoxManage controlvm reset — the hard reboot beyond the stop→start chain (no guest shutdown; like pressing the reset button).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Reset task queued"
//	@Failure		400	"Machine is not running"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/reset [post]
func (s *Server) handleResetMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Can only reset a running machine")
		return
	}
	s.queueMachineOp(w, r, machine, machines.OpReset, tasks.PriorityHigh, nil,
		"Reset task queued successfully")
}

// handlePauseMachine queues a pause (`controlvm pause` — execution freezes in
// RAM; resume continues it, unlike suspend's save-to-disk).
//
//	@Summary		Pause a machine
//	@Description	Minimum role: operator. VBoxManage controlvm pause — execution freezes in RAM (resume continues it; unlike suspend's save-to-disk).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Pause task queued"
//	@Failure		400	"Machine is not running"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/pause [post]
func (s *Server) handlePauseMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Can only pause a running machine")
		return
	}
	s.queueMachineOp(w, r, machine, machines.OpPause, tasks.PriorityHigh, nil,
		"Pause task queued successfully")
}

// handleResumeMachine queues a resume (`controlvm resume`).
//
//	@Summary		Resume a paused machine
//	@Description	Minimum role: operator. VBoxManage controlvm resume.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Resume task queued"
//	@Failure		400	"Machine is not paused"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/resume [post]
func (s *Server) handleResumeMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusPaused {
		taskError(w, http.StatusBadRequest, "Can only resume a paused machine")
		return
	}
	s.queueMachineOp(w, r, machine, machines.OpResume, tasks.PriorityHigh, nil,
		"Resume task queued successfully")
}

// injectNMIResponse is POST /machines/{machineName}/nmi's synchronous answer.
type injectNMIResponse struct {
	Success     bool   `json:"success"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
}

// handleInjectNMI serves POST /machines/{machineName}/nmi — inject a
// non-maskable interrupt into the running machine (VBoxManage debugvm
// injectnmi): the diagnostic trigger for guest crash dumps / kernel
// debuggers, zoneweaver's bhyvectl --inject-nmi mirror (Mark's parity go
// 2026-07-12). Synchronous like the base's — the injection is instantaneous,
// no task row.
//
//	@Summary		Inject an NMI into a running machine
//	@Description	Minimum role: operator. VBoxManage debugvm injectnmi — a non-maskable interrupt into the running guest: the diagnostic trigger for guest crash dumps and kernel debuggers (zoneweaver's bhyvectl --inject-nmi, same wire on both agents). SYNCHRONOUS — the injection is instantaneous, no task row. What happens next is the guest's own policy (Windows: crash dump when configured; Linux: kernel NMI handler/panic per sysctl).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	injectNMIResponse	"NMI injected"
//	@Failure		400	"Machine is not running"
//	@Failure		404	"Machine not found"
//	@Failure		500	"VBoxManage debugvm failed"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/nmi [post]
func (s *Server) handleInjectNMI(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Can only inject an NMI into a running machine")
		return
	}
	if err := vbox.InjectNMI(r.Context(), exe, machine.VBoxTarget()); err != nil {
		slog.Error("inject nmi", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to inject NMI")
		return
	}
	slog.Info("nmi injected", "machine", machine.Name,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, injectNMIResponse{
		Success:     true,
		MachineName: machine.Name,
		Message:     "NMI injected",
	})
}

// handleMachineScreenshot serves a PNG of the running machine's framebuffer
// (`controlvm screenshotpng`) — the base's no-session screenshot endpoint;
// synchronous, no console session needed.
//
//	@Summary		Console screenshot
//	@Description	Minimum role: viewer (the machine-screenshot capability token). Synchronous PNG capture of the running machine's framebuffer (VBoxManage controlvm screenshotpng) — no console session or extpack needed.
//	@Tags			Console
//	@Produce		png
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{file}	binary	"PNG screenshot"
//	@Failure		404	"Machine not found"
//	@Failure		502	"Machine not running, or capture failed"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/vnc/screenshot [get]
func (s *Server) handleMachineScreenshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadGateway, "Machine is not running — no framebuffer to capture")
		return
	}

	// A temp DIRECTORY, not a pre-created file: VBoxManage itself writes the
	// PNG — the agent never opens a write handle here (one write path rule).
	dir, err := os.MkdirTemp("", "hw-screenshot-")
	if err != nil {
		slog.Error("screenshot temp dir", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to capture screenshot")
		return
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	path := filepath.Join(dir, "screen.png")

	if serr := vbox.Screenshot(r.Context(), exe, machine.VBoxTarget(), path); serr != nil {
		slog.Error("screenshot capture", "machine", machine.Name, "error", serr)
		taskError(w, http.StatusBadGateway, "Failed to capture screenshot")
		return
	}
	png, err := os.ReadFile(filepath.Clean(path))
	if err != nil || len(png) == 0 {
		taskError(w, http.StatusBadGateway, "Failed to capture screenshot")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if _, werr := w.Write(png); werr != nil {
		slog.Error("write screenshot response", "error", werr)
	}
}

// handleListSnapshots serves the machine's snapshot tree (read-only,
// synchronous — VBoxManage snapshot list; qemu-img snapshot -l on utm, where
// even the list needs the stopped machine's qcow2 write lock).
//
//	@Summary		List a machine's snapshots
//	@Description	Minimum role: viewer (the machine-snapshots capability token). Synchronous — the live VirtualBox snapshot tree. node encodes the tree position (SnapshotName, SnapshotName-1, SnapshotName-1-1, ...); current marks the snapshot the machine's state derives from.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"The snapshot tree (empty array when none)"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/snapshots [get]
func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		if machines.UTMCtlPath(r.Context()) == "" {
			taskError(w, http.StatusServiceUnavailable, "UTM is not installed")
			return
		}
		switch liveMachineStatus(r.Context(), machine) {
		case "not_found":
			taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
			return
		case machines.StatusStopped:
		default:
			taskError(w, http.StatusBadRequest, "utm snapshots are offline (qemu-img) — stop the machine first")
			return
		}
		names, err := utm.ListSnapshots(r.Context(), machine.VBoxTarget())
		if errors.Is(err, utm.ErrNotFound) {
			taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
			return
		}
		if err != nil {
			slog.Error("list snapshots", "machine", machine.Name, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to list snapshots")
			return
		}
		// qemu-img knows only names — uuid/description/node/current stay absent.
		rows := make([]map[string]any, 0, len(names))
		for _, name := range names {
			rows = append(rows, map[string]any{"name": name})
		}
		writeJSON(w, map[string]any{
			"machine_name": machine.Name,
			"snapshots":    rows,
			"total":        len(rows),
		})
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	list, err := vbox.ListSnapshots(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("list snapshots", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list snapshots")
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"snapshots":    list,
		"total":        len(list),
	})
}

// snapshotMetadataJSON serializes the snapshot task metadata document.
func snapshotMetadataJSON(name, description string, live bool) (*string, error) {
	raw, err := json.Marshal(map[string]any{
		"snapshot_name": name,
		"description":   description,
		"live":          live,
	})
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// snapshotNamePattern is the snapshot name/prefix vocabulary shared with
// zoneweaver (its SNAPSHOT_NAME_PATTERN).
var snapshotNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

// handleTakeSnapshot queues snapshot_take: body {name} OR {prefix,
// retention?} (Snapshoter-style rotation naming <prefix>-YYYYMMDD-HHMM with
// keep-newest-N pruning — zoneweaver's take contract), plus description?,
// quiesce? (qga fsfreeze around the take), live? (--live, no pause).
//
//	@Summary		Take a snapshot
//	@Description	Minimum role: operator. Queues snapshot_take (VBoxManage snapshot take). Works on running and stopped machines; live=true avoids pausing a running machine. Body carries a literal name, OR prefix (+ retention) — the Snapshoter-style rotation contract shared with zoneweaver: the snapshot is named <prefix>-YYYYMMDD-HHMM and retention keeps the newest N <prefix>-* snapshots after the take (0 = keep all; on this hypervisor pruning is a physical disk merge — keep retention low). quiesce runs qga fsfreeze around the take when the guest agent answers (application-consistent; a silent channel narrates and the snapshot proceeds crash-consistent). The scheduled rotation service (config snapshots.*, per-machine override via the PUT snapshots field) queues this same operation. UTM MACHINES: snapshots are OFFLINE qemu-img operations against the bundle qcow2 — the machine must be STOPPED, and live/quiesce/description narrate as skipped.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Snapshot task queued"
//	@Failure		400	"Missing name/prefix, or unsupported characters"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/snapshots [post]
func (s *Server) handleTakeSnapshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Name        string `json:"name"`
		Prefix      string `json:"prefix"`
		Retention   int    `json:"retention"`
		Description string `json:"description"`
		Quiesce     bool   `json:"quiesce"`
		Live        bool   `json:"live"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" && body.Prefix == "" {
		taskError(w, http.StatusBadRequest, "name or prefix is required")
		return
	}
	label := body.Name
	if label == "" {
		label = body.Prefix
	}
	if !snapshotNamePattern.MatchString(label) {
		taskError(w, http.StatusBadRequest, "snapshot name/prefix contains unsupported characters")
		return
	}
	if body.Retention < 0 {
		body.Retention = 0
	}
	raw, err := json.Marshal(map[string]any{
		"snapshot_name": body.Name,
		"prefix":        body.Prefix,
		"retention":     body.Retention,
		"description":   body.Description,
		"quiesce":       body.Quiesce,
		"live":          body.Live,
	})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue snapshot task")
		return
	}
	metadata := string(raw)
	s.queueMachineOp(w, r, machine, machines.OpSnapshotTake, tasks.PriorityMedium, &metadata,
		"Snapshot task queued successfully")
}

// snapshotNameFromPath reads and validates the {snapshotName} path value.
func snapshotNameFromPath(w http.ResponseWriter, r *http.Request) string {
	name := r.PathValue("snapshotName")
	if name == "" {
		taskError(w, http.StatusBadRequest, "snapshot name is required")
		return ""
	}
	return name
}

// handleRestoreSnapshot queues snapshot_restore (machine must be stopped —
// the executor refuses running machines with a clear message).
//
//	@Summary		Restore a snapshot
//	@Description	Minimum role: operator. Queues snapshot_restore — the machine reverts to the snapshot's state. VirtualBox only restores powered-off machines; the task fails with guidance while it runs. UTM machines restore offline via qemu-img (stopped only).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			snapshotName	path	string	true	"Snapshot name"
//	@Success		200	{object}	queuedOperation	"Restore task queued"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/snapshots/{snapshotName}/restore [post]
func (s *Server) handleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	name := snapshotNameFromPath(w, r)
	if name == "" {
		return
	}
	metadata, err := snapshotMetadataJSON(name, "", false)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue snapshot restore task")
		return
	}
	s.queueMachineOp(w, r, machine, machines.OpSnapshotRestore, tasks.PriorityHigh, metadata,
		"Snapshot restore task queued successfully")
}

// handleDeleteSnapshot queues snapshot_delete.
//
//	@Summary		Delete a snapshot
//	@Description	Minimum role: operator. Queues snapshot_delete — the snapshot's state merges into its children.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			snapshotName	path	string	true	"Snapshot name"
//	@Success		200	{object}	queuedOperation	"Snapshot delete task queued"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/snapshots/{snapshotName} [delete]
func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	name := snapshotNameFromPath(w, r)
	if name == "" {
		return
	}
	metadata, err := snapshotMetadataJSON(name, "", false)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue snapshot delete task")
		return
	}
	s.queueMachineOp(w, r, machine, machines.OpSnapshotDelete, tasks.PriorityMedium, metadata,
		"Snapshot delete task queued successfully")
}

// handleModifySnapshot queues snapshot_modify (PUT — rename and/or
// description edit, zoneweaver's converged wire 2026-07-17): body {new_name?,
// description?}, either or both, 400 when neither. Pointers distinguish
// absent from empty — description present-but-empty ("") CLEARS the text.
//
//	@Summary		Modify a snapshot
//	@Description	Minimum role: operator. Queues snapshot_modify (VBoxManage snapshot edit): new_name renames the snapshot, description replaces its description — either or both; an explicit "" description CLEARS it, and a body carrying neither field is a 400. Not supported on utm machines (qemu-img cannot rename) — the task fails honestly.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			snapshotName	path	string	true	"Snapshot name"
//	@Success		200	{object}	queuedOperation	"Snapshot modify task queued"
//	@Failure		400	"Neither new_name nor description supplied"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/snapshots/{snapshotName} [put]
func (s *Server) handleModifySnapshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	name := snapshotNameFromPath(w, r)
	if name == "" {
		return
	}
	var body struct {
		NewName     *string `json:"new_name"`
		Description *string `json:"description"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.NewName == nil && body.Description == nil {
		taskError(w, http.StatusBadRequest, "new_name or description is required")
		return
	}
	if body.NewName != nil && !snapshotNamePattern.MatchString(*body.NewName) {
		taskError(w, http.StatusBadRequest, "snapshot name contains unsupported characters")
		return
	}
	raw, err := json.Marshal(struct {
		SnapshotName string  `json:"snapshot_name"`
		NewName      *string `json:"new_name,omitempty"`
		Description  *string `json:"description,omitempty"`
	}{name, body.NewName, body.Description})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue snapshot modify task")
		return
	}
	metadata := string(raw)
	s.queueMachineOp(w, r, machine, machines.OpSnapshotModify, tasks.PriorityMedium, &metadata,
		"Snapshot modify task queued successfully")
}

// handleGuestProperties serves the machine's full guest-property set
// (VBoxManage guestproperty enumerate) — the post-boot view: guest-additions
// IPs, OS info, and this agent's cloud-init keys. Read-only, synchronous.
//
//	@Summary		Enumerate guest properties
//	@Description	Minimum role: viewer. Synchronous VBoxManage guestproperty enumerate — the post-boot view: guest-additions data (/VirtualBox/GuestInfo/Net/* carries the guest's live IPs), OS info, and this agent's cloud-init keys.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Guest properties"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/guest-properties [get]
func (s *Server) handleGuestProperties(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	entries, err := vbox.EnumerateGuestProperties(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("enumerate guest properties", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to enumerate guest properties")
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"properties":   entries,
		"total":        len(entries),
	})
}

// clearPendingChangesResponse is DELETE /machines/{machineName}/pending-changes'
// answer: the top-level keys that were pending, now cleared.
type clearPendingChangesResponse struct {
	Success     bool     `json:"success"`
	MachineName string   `json:"machine_name"`
	ClearedKeys []string `json:"cleared_keys"`
	Message     string   `json:"message"`
}

// handleClearPendingChanges cancels the machine's accrued pending changes
// (the accrue-changes contract's cancel path — v1 clears the whole set).
//
//	@Summary		Cancel accrued pending changes
//	@Description	Minimum role: operator. Clears the machine's WHOLE pending set (the accrue-changes contract's cancel path — there is no per-key cancel; re-PUT the old value instead). Idempotent: clearing an empty set succeeds with an empty cleared_keys.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	clearPendingChangesResponse	"Pending changes cleared"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/pending-changes [delete]
func (s *Server) handleClearPendingChanges(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	pending := machines.ParseConfiguration(machine).Section("pending_changes")
	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if err := s.machines.ClearPendingChanges(r.Context(), machine.Name); err != nil {
		slog.Error("clear pending changes", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to clear pending changes")
		return
	}
	slog.Info("pending changes cleared", "machine", machine.Name,
		"keys", len(keys), "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, clearPendingChangesResponse{
		Success:     true,
		MachineName: machine.Name,
		ClearedKeys: keys,
		Message:     "Pending changes cleared",
	})
}

// handleApplyPendingChanges applies the accrued pending changes NOW, without
// a power transition — the stopped-with-pending case (machine shut down from
// inside the guest or the GUI, user wants the changes in without booting).
//
//	@Summary		Apply accrued pending changes now
//	@Description	Minimum role: operator. Queues the machine_modify apply immediately, WITHOUT a power transition — for a machine that accrued changes while running and then got shut down outside the agent (inside the guest, or the VirtualBox GUI). The machine must be powered off; anything else answers 400 (the changes apply automatically at the next agent-driven power cycle anyway). Success clears the pending set.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	queuedOperation	"Apply task queued"
//	@Failure		400	"No pending changes, or machine is not powered off"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName}/pending-changes/apply [post]
func (s *Server) handleApplyPendingChanges(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	pending := machines.ParseConfiguration(machine).Section("pending_changes")
	if len(pending) == 0 {
		taskError(w, http.StatusBadRequest, "No pending changes to apply")
		return
	}
	switch liveMachineStatus(r.Context(), machine) {
	case machines.StatusStopped, machines.StatusAborted:
	default:
		taskError(w, http.StatusBadRequest,
			"Machine must be powered off to apply pending changes now — they apply automatically at the next agent-driven power cycle")
		return
	}
	task := s.queuePendingApply(r.Context(), machine, nil, auth.FromContext(r.Context()).Name)
	if task == nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue pending-changes apply")
		return
	}
	operationResponse(w, task.ID, machine.Name, machines.OpModify, tasks.StatusPending,
		"Pending changes apply queued")
}

// handleDeleteMachine: running machines need force=true, which chains a
// CRITICAL stop before the CRITICAL delete.
//
//	@Summary		Delete a machine
//	@Description	Minimum role: operator. Running machines need force=true, which chains a CRITICAL stop before the CRITICAL delete. The machine is powered off if still running, unregistered from VirtualBox — with media deletion when cleanup_disks (default true) — its working directory removed (only when it sits under the machines root), its registry row removed, and its leftover pending tasks cancelled. SAFETY — the PROVENANCE STAMP rule (typed disk spec, converged sync 2026-07-17; it replaced the workdir-prefix heuristic): before the unregister, every attached medium is checked for the agent's stamp (the hyperweaver:source medium property, .hw-source sidecar fallback — written when the agent CREATED the medium: template clones, blank VDIs). Stamped = ours, cleanup_disks destroys it; UNSTAMPED = foreign (image attaches, external ISOs, pre-stamp media) — detached and preserved with a narrated skip, wherever it lives. One honest caveat, narrated in the task output: cleanup_disks also removes the working directory, so a foreign medium whose FILE sits inside it still goes with the directory. cleanup_disks=false unregisters only — every medium file and the working directory stay on disk. GET /media lists every registered medium with its stamp.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			cleanup_disks	query	boolean	false	"false preserves every medium file and the working directory (the base's keep-datasets default, as an explicit flag)"
//	@Success		200	{object}	map[string]interface{}	"Delete tasks queued"
//	@Failure		400	"Machine is running and force is not set"
//	@Failure		404	"Machine not found"
//	@Router			/machines/{machineName} [delete]
func (s *Server) handleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	force := r.URL.Query().Get("force") == "true"
	// cleanup_disks defaults TRUE (agent-created media die with the machine);
	// false preserves every medium file and the working directory. Media
	// OUTSIDE the working directory (user-attached disk images) are ALWAYS
	// preserved regardless — the executor detaches them first.
	cleanupDisks := r.URL.Query().Get("cleanup_disks") != "false"
	createdBy := auth.FromContext(r.Context()).Name

	status := liveMachineStatus(r.Context(), machine)
	if status == machines.StatusRunning && !force {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"error":          "Machine is running. Use force=true to stop and delete",
			"current_status": status,
		}); err != nil {
			slog.Error("write machine error response", "error", err)
		}
		return
	}

	taskIDs := []string{}
	var dependsOn *string
	if status == machines.StatusRunning {
		metadata, merr := stopMetadataJSON(true)
		if merr != nil {
			slog.Error("serialize stop metadata", "error", merr)
			taskError(w, http.StatusInternalServerError, "Failed to queue delete tasks")
			return
		}
		stopTask, serr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: machine.Name,
			Operation:   machines.OpStop,
			Priority:    tasks.PriorityCritical,
			CreatedBy:   createdBy,
			Metadata:    metadata,
		})
		if serr != nil {
			slog.Error("queue delete stop task", "machine", machine.Name, "error", serr)
			taskError(w, http.StatusInternalServerError, "Failed to queue delete tasks")
			return
		}
		taskIDs = append(taskIDs, stopTask.ID)
		dependsOn = &stopTask.ID
	}

	deleteRaw, err := json.Marshal(map[string]bool{"cleanup_disks": cleanupDisks})
	if err != nil {
		slog.Error("serialize delete metadata", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue delete tasks")
		return
	}
	deleteMeta := string(deleteRaw)
	deleteTask, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpDelete,
		Priority:    tasks.PriorityCritical,
		CreatedBy:   createdBy,
		DependsOn:   dependsOn,
		Metadata:    &deleteMeta,
	})
	if err != nil {
		slog.Error("queue delete task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue delete tasks")
		return
	}
	taskIDs = append(taskIDs, deleteTask.ID)

	writeJSON(w, map[string]any{
		"success":       true,
		"delete_tasks":  taskIDs,
		"machine_name":  machine.Name,
		"operation":     machines.OpDelete,
		"status":        tasks.StatusPending,
		"message":       "Delete tasks queued successfully",
		"force":         force,
		"cleanup_disks": cleanupDisks,
	})
}
