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
	Machines json.RawMessage `json:"machines"`
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
	skipped := []map[string]string{}
	taskIDs := []string{}
	for _, machine := range targets {
		status := liveMachineStatus(r.Context(), machine)
		if reason := skipReason(status); reason != "" {
			skipped = append(skipped, map[string]string{"machine": machine.Name, "reason": reason})
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
			skipped = append(skipped, map[string]string{"machine": machine.Name, "reason": "queue_failed"})
			continue
		}
		taskIDs = append(taskIDs, task.ID)
	}

	writeJSON(w, map[string]any{
		"success":       true,
		"operation":     operationLabel,
		"tasks_created": len(taskIDs),
		"skipped":       skipped,
		"task_ids":      taskIDs,
		"message":       formatBulkMessage(operation, len(taskIDs), len(skipped)),
	})
}

func formatBulkMessage(operation string, created, skipped int) string {
	return fmt.Sprintf("%d %s tasks queued, %d skipped", created, operation, skipped)
}

// handleServerIDs lists used server_ids, constraints, and the next free id.
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
	writeJSON(w, map[string]any{
		"used": used,
		"constraints": map[string]any{
			"format":     "numeric",
			"min_length": 4,
			"max_length": 8,
			"min_value":  1,
			"max_value":  99999999,
		},
		"next_available": next,
		"total_used":     len(used),
	})
}

// handleNextServerID returns just the next free server_id.
func (s *Server) handleNextServerID(w http.ResponseWriter, r *http.Request) {
	next, err := s.machines.NextServerID(r.Context(), s.cfg.Machines.ServerIDStart)
	if err != nil {
		slog.Error("compute next server id", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to generate next server ID")
		return
	}
	writeJSON(w, map[string]any{"server_id": next})
}
