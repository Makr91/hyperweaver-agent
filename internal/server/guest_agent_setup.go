package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// handleGuestAgentSetup serves POST /machines/{machineName}/guest-agent/setup
// — opt an existing machine into the guest-agent UART (creates wire it only
// when the spec says zones.guest_agent: true): the COM2→pipe serial config
// rides the ordinary modify machinery, queued against a powered-off machine,
// accrued for the next power cycle otherwise (the vrde-tls pattern).
//
//	@Summary		Wire the guest-agent UART onto an existing machine
//	@Description	Minimum role: operator. Machines created with vbox.guest_agent: true get the UART at build — this opts in everything else (existing machines, discovered VMs, creates that omitted the flag): vbox.serial port 2 (0x2F8/IRQ3, uart-mode server onto the machine's deterministic pipe) rides the ordinary modify machinery — a machine_modify task against a powered-off machine, the accrue-changes contract (pending_power_cycle) otherwise. The GUEST half must run qemu-ga on its COM2 (current box templates bake the auto-transport config in; older guests need it added). A document that claims serial port 2 itself is never overridden at create; this endpoint is the explicit override.
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string						true	"Machine name"
//	@Success		200			{object}	map[string]interface{}		"Setup queued (powered off) or accrued (pending_power_cycle)"
//	@Failure		404			{object}	taskErrorBody				"Machine not found, or no VM exists behind it yet"
//	@Failure		503			{object}	taskErrorBody				"VirtualBox is not installed, or the guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest-agent/setup [post]
func (s *Server) handleGuestAgentSetup(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		taskError(w, http.StatusBadRequest,
			"the guest-agent UART is VirtualBox plumbing — utm guests use qemu-guest-agent via utmctl already")
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("guest-agent setup probe", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to read machine state")
		return
	}
	pipe, err := s.machineQGAPipe(machine)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to resolve the guest-agent channel")
		return
	}

	doc := map[string]any{
		"vbox": map[string]any{
			"serial": []any{map[string]any{
				"port":    2,
				"io_base": "0x2F8",
				"irq":     3,
				"mode":    "server " + pipe,
			}},
		},
	}
	switch machines.MapVBoxState(info.State) {
	case machines.StatusStopped, machines.StatusAborted:
		metadata, merr := json.Marshal(doc)
		if merr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to queue the guest-agent setup")
			return
		}
		metadataStr := string(metadata)
		task, terr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: machine.Name,
			Operation:   machines.OpModify,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
			Metadata:    &metadataStr,
		})
		if terr != nil {
			slog.Error("queue guest-agent setup", "machine", machine.Name, "error", terr)
			taskError(w, http.StatusInternalServerError, "Failed to queue the guest-agent setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"task_id":          task.ID,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           tasks.StatusPending,
			"requires_restart": true,
			"pipe":             pipe,
			"message":          "Guest-agent UART setup queued (machine is powered off) — the guest needs qemu-ga on its COM2 (baked into current box templates).",
		})
	default:
		merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, doc)
		if merr != nil {
			slog.Error("accrue guest-agent setup", "machine", machine.Name, "error", merr)
			taskError(w, http.StatusInternalServerError, "Failed to store the guest-agent setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           "pending_power_cycle",
			"requires_restart": true,
			"pending_changes":  merged,
			"pipe":             pipe,
			"message":          "Guest-agent UART setup accrued — applies at the next agent-driven power cycle; the guest needs qemu-ga on its COM2 (baked into current box templates).",
		})
	}
}
