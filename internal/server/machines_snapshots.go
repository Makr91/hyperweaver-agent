package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

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
