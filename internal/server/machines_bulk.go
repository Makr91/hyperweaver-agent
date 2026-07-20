package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Bulk machine operations and server-id endpoints (Agent API v1 machines
// surface). Bulk start/stop queue tasks across many machines at once;
// /machines/ids serves the server_id registry.

// bulkRequest is the bulk body: "all" or a name array.
type bulkRequest struct {
	// "all" or an array of machine names
	Machines json.RawMessage `json:"machines"`
}

// bulkSkip is one skipped machine in a bulk start/stop response.
type bulkSkip struct {
	Machine string `json:"machine"`
	Reason  string `json:"reason"`
}

// bulkResponse is the 200 body of POST /machines/bulk/start and
// /machines/bulk/stop.
type bulkResponse struct {
	Success bool `json:"success"`
	// bulk_start or bulk_stop
	Operation    string     `json:"operation"`
	TasksCreated int        `json:"tasks_created"`
	Skipped      []bulkSkip `json:"skipped"`
	TaskIDs      []string   `json:"task_ids"`
	Message      string     `json:"message"`
}

// errInvalidBulkBody reports a bulk body that is neither "all" nor a name
// array — the caller answers 400 with this text.
var errInvalidBulkBody = errors.New(`machines must be "all" or an array of machine names`)

// resolveBulkTargets expands the bulk body into machine rows.
func (s *Server) resolveBulkTargets(ctx context.Context, raw json.RawMessage, wantStatus []string) ([]*machines.Machine, error) {
	var all string
	if err := json.Unmarshal(raw, &all); err == nil {
		if all != "all" {
			return nil, errInvalidBulkBody
		}
		orphaned := false
		list, lerr := s.machines.List(ctx, &machines.ListFilter{Orphaned: &orphaned})
		if lerr != nil {
			return nil, lerr
		}
		targets := []*machines.Machine{}
		for _, m := range list {
			for _, status := range wantStatus {
				if m.Status == status {
					targets = append(targets, m)
					break
				}
			}
		}
		return targets, nil
	}

	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, errInvalidBulkBody
	}
	targets := []*machines.Machine{}
	for _, name := range names {
		m, gerr := s.machines.Get(ctx, name)
		if errors.Is(gerr, machines.ErrNotFound) {
			continue
		}
		if gerr != nil {
			return nil, gerr
		}
		targets = append(targets, m)
	}
	return targets, nil
}

// handleBulkStart queues start tasks for many machines at once.
//
//	@Summary		Bulk start machines
//	@Description	Minimum role: operator. machines is "all" (every stopped, non-orphaned machine) or a name array; already-running machines are skipped with a reason. Per machine, accrued pending changes apply first (start chained on the modify), same as the single start.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body	bulkRequest	true	"all or an array of machine names"
//	@Success		200	{object}	bulkResponse	"Bulk start queued"
//	@Router			/machines/bulk/start [post]
func (s *Server) handleBulkStart(w http.ResponseWriter, r *http.Request) {
	s.handleBulk(w, r, "bulk_start", machines.OpStart, tasks.PriorityMedium,
		[]string{machines.StatusStopped, machines.StatusConfigured, machines.StatusAborted, machines.StatusSuspended},
		func(status string) (skip string) {
			if status == machines.StatusRunning {
				return "already_running"
			}
			return ""
		})
}

// handleBulkStop queues stop tasks for many machines at once.
//
//	@Summary		Bulk stop machines
//	@Description	Minimum role: operator. machines is "all" (every running, non-orphaned machine) or a name array; already-stopped machines are skipped with a reason. Pending starts for targeted machines are cancelled. Per machine, accrued pending changes apply after the power-off, same as the single stop.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			request	body	bulkRequest	true	"all or an array of machine names"
//	@Success		200	{object}	bulkResponse	"Bulk stop queued"
//	@Router			/machines/bulk/stop [post]
func (s *Server) handleBulkStop(w http.ResponseWriter, r *http.Request) {
	s.handleBulk(w, r, "bulk_stop", machines.OpStop, tasks.PriorityHigh,
		[]string{machines.StatusRunning},
		func(status string) (skip string) {
			switch status {
			case machines.StatusStopped, machines.StatusConfigured:
				return "already_stopped"
			case "not_found":
				return "not_found_on_system"
			}
			return ""
		})
}

// handleBulk implements the shared bulk-operation flow: resolve targets,
// live-check each, queue tasks for the eligible, report the skipped.
func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request, operationLabel, operation string,
	priority int, allStatuses []string, skipReason func(status string) string,
) {
	var body bulkRequest
	if err := decodeBody(r, &body); err != nil || body.Machines == nil {
		taskError(w, http.StatusBadRequest, `machines field is required (array of names or "all")`)
		return
	}

	targets, err := s.resolveBulkTargets(r.Context(), body.Machines, allStatuses)
	if errors.Is(err, errInvalidBulkBody) {
		taskError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		slog.Error("resolve bulk targets", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue bulk tasks")
		return
	}

	createdBy := auth.FromContext(r.Context()).Name
	skipped := []bulkSkip{}
	taskIDs := []string{}
	for _, machine := range targets {
		status := liveMachineStatus(r.Context(), machine)
		if reason := skipReason(status); reason != "" {
			skipped = append(skipped, bulkSkip{Machine: machine.Name, Reason: reason})
			continue
		}
		// machines.provision_on_start applies to bulk starts too: a
		// never-provisioned machine with a stored document boots through the
		// provision pipeline (the returned id is the orchestration parent).
		if operation == machines.OpStart {
			if parentID, ok := s.provisionOnStartPipeline(r.Context(), machine, createdBy); ok {
				taskIDs = append(taskIDs, parentID)
				continue
			}
		}
		nt := tasks.NewTask{
			MachineName: machine.Name,
			Operation:   operation,
			Priority:    priority,
			CreatedBy:   createdBy,
		}
		// The accrue-changes contract rides bulk operations too: starts apply
		// pending changes first, stops chain the apply after the power-off.
		if operation == machines.OpStart {
			if applyTask := s.queuePendingApply(r.Context(), machine, nil, createdBy); applyTask != nil {
				nt.DependsOn = &applyTask.ID
			}
		}
		if operation == machines.OpStop {
			s.cancelPendingStarts(r.Context(), machine.Name)
			metadata, merr := stopMetadataJSON(false)
			if merr != nil {
				slog.Error("serialize stop metadata", "error", merr)
				continue
			}
			nt.Metadata = metadata
		}
		task, cerr := s.tasks.Store().Create(r.Context(), &nt)
		if cerr != nil {
			slog.Error("queue bulk task", "machine", machine.Name, "error", cerr)
			skipped = append(skipped, bulkSkip{Machine: machine.Name, Reason: "queue_failed"})
			continue
		}
		if operation == machines.OpStop {
			s.queuePendingApply(r.Context(), machine, &task.ID, createdBy)
		}
		taskIDs = append(taskIDs, task.ID)
	}

	writeJSON(w, bulkResponse{
		Success:      true,
		Operation:    operationLabel,
		TasksCreated: len(taskIDs),
		Skipped:      skipped,
		TaskIDs:      taskIDs,
		Message:      formatBulkMessage(operation, len(taskIDs), len(skipped)),
	})
}

func formatBulkMessage(operation string, created, skipped int) string {
	return fmt.Sprintf("%d %s tasks queued, %d skipped", created, operation, skipped)
}

// serverIDConstraints is GET /machines/ids' constraints block — the
// server_id vocabulary (numeric, 4-8 digits).
type serverIDConstraints struct {
	Format    string `json:"format"`
	MinLength int    `json:"min_length"`
	MaxLength int    `json:"max_length"`
	MinValue  int    `json:"min_value"`
	MaxValue  int    `json:"max_value"`
}

// serverIDsResponse is GET /machines/ids's answer.
type serverIDsResponse struct {
	Used          []machines.UsedServerID `json:"used"`
	Constraints   serverIDConstraints     `json:"constraints"`
	NextAvailable string                  `json:"next_available"`
	TotalUsed     int                     `json:"total_used"`
}

// handleServerIDs lists used server_ids, constraints, and the next free id.
//
//	@Summary		Server ID usage
//	@Description	Minimum role: viewer. Used server_ids, constraints, and the next available id — create NEVER auto-assigns (with prefix_machine_names the caller must send settings.server_id; this endpoint and /machines/ids/next feed the field).
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	serverIDsResponse	"Server ID information"
//	@Router			/machines/ids [get]
func (s *Server) handleServerIDs(w http.ResponseWriter, r *http.Request) {
	used, err := s.machines.UsedServerIDs(r.Context())
	if err != nil {
		slog.Error("list server ids", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve server ID information")
		return
	}
	next, err := s.machines.NextServerID(r.Context(), s.cfg.Machines.ServerIDStart)
	if err != nil {
		slog.Error("compute next server id", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve server ID information")
		return
	}
	writeJSON(w, serverIDsResponse{
		Used: used,
		Constraints: serverIDConstraints{
			Format:    "numeric",
			MinLength: 4,
			MaxLength: 8,
			MinValue:  1,
			MaxValue:  99999999,
		},
		NextAvailable: next,
		TotalUsed:     len(used),
	})
}

// nextServerIDResponse is GET /machines/ids/next's answer.
type nextServerIDResponse struct {
	ServerID string `json:"server_id"`
}

// handleNextServerID returns just the next free server_id.
//
//	@Summary		Next available server ID
//	@Description	Minimum role: viewer.
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	nextServerIDResponse	"Next server ID"
//	@Router			/machines/ids/next [get]
func (s *Server) handleNextServerID(w http.ResponseWriter, r *http.Request) {
	next, err := s.machines.NextServerID(r.Context(), s.cfg.Machines.ServerIDStart)
	if err != nil {
		slog.Error("compute next server id", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to generate next server ID")
		return
	}
	writeJSON(w, nextServerIDResponse{ServerID: next})
}
