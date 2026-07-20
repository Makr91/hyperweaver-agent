package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

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
