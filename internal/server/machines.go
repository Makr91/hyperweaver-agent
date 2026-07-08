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

// handleStartMachine queues a start task — one native VBoxManage boot for
// every machine (the provision pipeline queues this same operation as its
// boot child).
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

	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: machine.Name,
		Operation:   machines.OpStart,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
	})
	if err != nil {
		slog.Error("queue start task", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue start task")
		return
	}
	operationResponse(w, task.ID, machine.Name, machines.OpStart, tasks.StatusPending,
		"Start task queued successfully")
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

// handleMachineScreenshot serves a PNG of the running machine's framebuffer
// (`controlvm screenshotpng`) — the base's no-session screenshot endpoint;
// synchronous, no console session needed.
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
// synchronous — VBoxManage snapshot list).
func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
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

// handleTakeSnapshot queues snapshot_take: body {name, description?, live?}.
func (s *Server) handleTakeSnapshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Live        bool   `json:"live"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" {
		taskError(w, http.StatusBadRequest, "name is required")
		return
	}
	metadata, err := snapshotMetadataJSON(body.Name, body.Description, body.Live)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue snapshot task")
		return
	}
	s.queueMachineOp(w, r, machine, machines.OpSnapshotTake, tasks.PriorityMedium, metadata,
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

// handleGuestProperties serves the machine's full guest-property set
// (VBoxManage guestproperty enumerate) — the post-boot view: guest-additions
// IPs, OS info, and this agent's cloud-init keys. Read-only, synchronous.
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

// handleDeleteMachine: running machines need force=true, which chains a
// CRITICAL stop before the CRITICAL delete.
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
