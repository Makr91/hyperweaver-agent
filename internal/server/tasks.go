package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Task queue endpoints (Agent API v1). Paths, query parameters, payloads,
// and error shapes mirror the Node agent's TaskQueue controllers — the
// Hyperweaver UI's Tasks surface codes against that exact wire. The one
// deliberate divergence (D-F): DELETE /tasks/{taskId} cancels running tasks
// too, not just pending ones.

// taskError writes the task controllers' error shape: {"error": "..."}.
func taskError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		slog.Error("write task error response", "error", err)
	}
}

// handleListTasks mirrors GET /tasks: filterable, sortable, limited, with
// total included only on request (include_count=true).
func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := tasks.ListFilter{
		Status:       query.Get("status"),
		MachineName:  query.Get("machine_name"),
		Operation:    query.Get("operation"),
		OperationNot: query.Get("operation_ne"),
		ParentTaskID: query.Get("parent_task_id"),
		Sort:         query.Get("sort"),
		Order:        query.Get("order"),
		Limit:        s.cfg.Tasks.DefaultPaginationLimit,
	}
	if raw := query.Get("limit"); raw != "" {
		if limit, err := strconv.Atoi(raw); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}
	if raw := query.Get("min_priority"); raw != "" {
		if minPriority, err := strconv.Atoi(raw); err == nil {
			filter.MinPriority = &minPriority
		}
	}
	if raw := query.Get("since"); raw != "" {
		if since, err := time.Parse(time.RFC3339, raw); err == nil {
			filter.Since = &since
		}
	}

	list, err := s.tasks.Store().List(r.Context(), &filter)
	if err != nil {
		slog.Error("list tasks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve tasks")
		return
	}

	response := map[string]any{
		"tasks":         list,
		"running_count": s.tasks.RunningCount(),
	}
	if query.Get("include_count") == "true" {
		total, cerr := s.tasks.Store().Count(r.Context(), &filter)
		if cerr != nil {
			slog.Error("count tasks", "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to retrieve tasks")
			return
		}
		response["total"] = total
	}
	writeJSON(w, response)
}

// handleTaskStats mirrors GET /tasks/stats.
func (s *Server) handleTaskStats(w http.ResponseWriter, r *http.Request) {
	counts, err := s.tasks.Store().StatusCounts(r.Context())
	if err != nil {
		slog.Error("task stats", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve task statistics")
		return
	}
	writeJSON(w, map[string]any{
		"pending_tasks":          counts[tasks.StatusPending],
		"running_tasks":          s.tasks.RunningCount(),
		"completed_tasks":        counts[tasks.StatusCompleted],
		"failed_tasks":           counts[tasks.StatusFailed],
		"cancelled_tasks":        counts[tasks.StatusCancelled],
		"max_concurrent_tasks":   s.tasks.MaxConcurrent(),
		"task_processor_running": s.tasks.ProcessorRunning(),
	})
}

// handleTaskDetails mirrors GET /tasks/{taskId}.
func (s *Server) handleTaskDetails(w http.ResponseWriter, r *http.Request) {
	task, err := s.tasks.Store().Get(r.Context(), r.PathValue("taskId"))
	if errors.Is(err, tasks.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Task not found")
		return
	}
	if err != nil {
		slog.Error("get task details", "error", err, "task_id", r.PathValue("taskId"))
		taskError(w, http.StatusInternalServerError, "Failed to retrieve task details")
		return
	}
	writeJSON(w, task)
}

// handleTaskOutput mirrors GET /tasks/{taskId}/output: the live in-memory
// buffer while the task runs, the persisted output afterwards.
func (s *Server) handleTaskOutput(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	task, err := s.tasks.Store().Get(r.Context(), taskID)
	if errors.Is(err, tasks.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Task not found")
		return
	}
	if err != nil {
		slog.Error("get task for output", "error", err, "task_id", taskID)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve task output")
		return
	}

	output, err := s.tasks.Output().GetOutput(r.Context(), taskID)
	if err != nil {
		slog.Error("get task output", "error", err, "task_id", taskID)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve task output")
		return
	}
	writeJSON(w, map[string]any{
		"task_id": taskID,
		"status":  task.Status,
		"output":  output,
	})
}

// handleCancelTask mirrors DELETE /tasks/{taskId}, extended per D-F: running
// tasks are cancellable too — the executor's children are killed and its
// cleanup runs; the task lands in cancelled with output preserved.
func (s *Server) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	taskID := r.PathValue("taskId")
	wasRunning, err := s.tasks.Cancel(r.Context(), taskID)

	var notCancellable *tasks.NotCancellableError
	switch {
	case errors.Is(err, tasks.ErrNotFound):
		taskError(w, http.StatusNotFound, "Task not found")
		return
	case errors.As(err, &notCancellable):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if werr := json.NewEncoder(w).Encode(map[string]string{
			"error":          "Can only cancel pending or running tasks",
			"current_status": notCancellable.Status,
		}); werr != nil {
			slog.Error("write task error response", "error", werr)
		}
		return
	case err != nil:
		slog.Error("cancel task", "error", err, "task_id", taskID)
		taskError(w, http.StatusInternalServerError, "Failed to cancel task")
		return
	}

	message := "Task cancelled successfully"
	if wasRunning {
		message = "Task cancellation requested"
	}
	slog.Info("task cancel requested", "task_id", taskID,
		"was_running", wasRunning, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"task_id": taskID,
		"message": message,
	})
}

// handleClearCompletedTasks mirrors DELETE /tasks/completed: hard-deletes
// every task in a terminal state.
func (s *Server) handleClearCompletedTasks(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.tasks.Store().DeleteFinished(r.Context())
	if err != nil {
		slog.Error("clear completed tasks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to clear completed tasks")
		return
	}
	slog.Info("completed tasks cleared", "deleted_count", deleted,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success":       true,
		"message":       "Deleted " + strconv.FormatInt(deleted, 10) + " completed/failed/cancelled tasks",
		"deleted_count": deleted,
	})
}
