package server

import (
	"log/slog"
	"net/http"
	"sort"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

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
