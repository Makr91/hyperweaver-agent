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

// liveMachineStatus asks VirtualBox for a machine's current state — the
// pre-operation idempotency check ("not_found" when no VM exists, matching
// the Node agent's getSystemZoneStatus contract). The UUID addresses the VM
// once known — a provisioned machine's VirtualBox name is Hosts.rb's own.
func liveMachineStatus(ctx context.Context, machine *machines.Machine) string {
	exe := machines.VBoxManagePath(ctx)
	if exe == "" {
		return "not_found"
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
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

// handleListMachines: status/orphaned filters, post-filter on tag,
// name-ascending.
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

	writeJSON(w, map[string]any{
		"machines": list,
		"total":    len(list),
	})
}

// handleMachineDetails: live status check (updating the registry when it
// drifted), the machine record, its live configuration, and its pending
// tasks.
func (s *Server) handleMachineDetails(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}

	systemStatus := liveMachineStatus(r.Context(), machine)
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

	writeJSON(w, map[string]any{
		"machine_info":       fresh,
		"configuration":      configuration,
		"active_vnc_session": nil,
		"pending_tasks":      active,
		"system_status":      systemStatus,
		"web_address":        webAddress,
	})
}

// handleMachineConfig: the live configuration document (VirtualBox's
// machinereadable view on this agent).
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
	payload := map[string]any{
		"success":      true,
		"machine_name": machineName,
		"operation":    operation,
		"status":       status,
		"message":      message,
	}
	if taskID != nil {
		payload["task_id"] = taskID
	}
	writeJSON(w, payload)
}

// handleStartMachine queues a start task. Provisioned machines get the
// decomposed pipeline (zoneweaver's orchestration model): a start parent
// anchor whose chained children — prepare, plugin check, vagrant up — the
// aggregation rolls up into coarse progress. Raw machines stay one task.
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

	createdBy := auth.FromContext(r.Context()).Name
	if machine.Provisioned() {
		parent, err := s.queueStartPipeline(r.Context(), machine.Name, createdBy)
		if err != nil {
			slog.Error("queue start pipeline", "machine", machine.Name, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to queue start task")
			return
		}
		operationResponse(w, parent.ID, machine.Name, machines.OpStart, tasks.StatusPending,
			"Start pipeline queued (prepare → plugin check → vagrant up)")
		return
	}

	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStart,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
	})
	if err != nil {
		slog.Error("queue start task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue start task")
		return
	}
	operationResponse(w, task.ID, machine.Name, machines.OpStart, tasks.StatusPending,
		"Start task queued successfully")
}

// queueStartPipeline creates the provisioned start's orchestration: a start
// parent anchor plus its chained children (zoneweaver's
// createZoneCreationSubTasks shape — every child carries parent_task_id and
// depends_on its predecessor). Cancelling the parent cascades down the chain.
func (s *Server) queueStartPipeline(ctx context.Context, machineName, createdBy string) (*tasks.Task, error) {
	parent, err := s.tasks.Store().Create(ctx, &tasks.NewTask{
		MachineName: machineName,
		Operation:   machines.OpStart,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		Parent:      true,
	})
	if err != nil {
		return nil, err
	}

	previous := ""
	for _, operation := range []string{machines.OpPrepare, machines.OpPluginCheck, machines.OpVagrantUp} {
		nt := tasks.NewTask{
			MachineName:  machineName,
			Operation:    operation,
			Priority:     tasks.PriorityMedium,
			CreatedBy:    createdBy,
			ParentTaskID: &parent.ID,
		}
		if previous != "" {
			dependsOn := previous
			nt.DependsOn = &dependsOn
		}
		child, cerr := s.tasks.Store().Create(ctx, &nt)
		if cerr != nil {
			// The cascade sweeps whatever children made it in.
			if _, xerr := s.tasks.Cancel(ctx, parent.ID); xerr != nil {
				slog.Warn("cancel half-built start pipeline", "task_id", parent.ID, "error", xerr)
			}
			return nil, cerr
		}
		previous = child.ID
	}
	return parent, nil
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
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStop,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue stop task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue stop task")
		return
	}
	operationResponse(w, task.ID, machine.Name, machines.OpStop, tasks.StatusPending,
		"Stop task queued successfully")
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
	startTask, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStart,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   createdBy,
		DependsOn:   &stopTask.ID,
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

// handleDeleteMachine: running machines need force=true, which chains a
// CRITICAL stop before the CRITICAL delete.
func (s *Server) handleDeleteMachine(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	force := r.URL.Query().Get("force") == "true"
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

	deleteTask, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpDelete,
		Priority:    tasks.PriorityCritical,
		CreatedBy:   createdBy,
		DependsOn:   dependsOn,
	})
	if err != nil {
		slog.Error("queue delete task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue delete tasks")
		return
	}
	taskIDs = append(taskIDs, deleteTask.ID)

	writeJSON(w, map[string]any{
		"success":      true,
		"delete_tasks": taskIDs,
		"machine_name": machine.Name,
		"operation":    machines.OpDelete,
		"status":       tasks.StatusPending,
		"message":      "Delete tasks queued successfully",
		"force":        force,
	})
}
