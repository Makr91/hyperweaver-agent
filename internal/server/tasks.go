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

// taskErrorBody is the task controllers' error shape: {"error": "..."}.
type taskErrorBody struct {
	Error string `json:"error"`
}

// taskError writes the task controllers' error shape: {"error": "..."}.
func taskError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(taskErrorBody{Error: message}); err != nil {
		slog.Error("write task error response", "error", err)
	}
}

// listTasksResponse is GET /tasks's answer.
type listTasksResponse struct {
	Tasks        []*tasks.Task `json:"tasks"`
	RunningCount int           `json:"running_count"`
	// Present only when include_count=true
	Total *int `json:"total,omitempty"`
}

// handleListTasks mirrors GET /tasks: filterable, sortable, limited, with
// total included only on request (include_count=true).
//
//	@Summary		List tasks
//	@Description	Minimum role: viewer. Filterable and sortable; the total count is computed only when include_count=true.
//	@Tags			Task Management
//	@Produce		json
//	@Param			status			query	string	false	"Filter by status"
//	@Param			machine_name	query	string	false	"Filter by machine name"
//	@Param			operation		query	string	false	"Filter by operation kind"
//	@Param			operation_ne	query	string	false	"Exclude one operation kind"
//	@Param			min_priority	query	int		false	"Minimum priority"
//	@Param			parent_task_id	query	string	false	"Filter by parent task id"
//	@Param			since			query	string	false	"Only tasks modified (updatedAt) at or after this time — incremental refresh"
//	@Param			limit			query	int		false	"Maximum tasks to return"
//	@Param			sort			query	string	false	"Sort field"
//	@Param			order			query	string	false	"Sort direction"
//	@Param			include_count	query	string	false	"Also return the total matching count"
//	@Success		200	{object}	listTasksResponse	"Tasks retrieved"
//	@Router			/tasks [get]
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

	response := listTasksResponse{
		Tasks:        list,
		RunningCount: s.tasks.RunningCount(),
	}
	if query.Get("include_count") == "true" {
		total, cerr := s.tasks.Store().Count(r.Context(), &filter)
		if cerr != nil {
			slog.Error("count tasks", "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to retrieve tasks")
			return
		}
		response.Total = &total
	}
	writeJSON(w, response)
}

// taskStatsResponse is GET /tasks/stats's answer.
type taskStatsResponse struct {
	PendingTasks         int  `json:"pending_tasks"`
	RunningTasks         int  `json:"running_tasks"`
	CompletedTasks       int  `json:"completed_tasks"`
	FailedTasks          int  `json:"failed_tasks"`
	CancelledTasks       int  `json:"cancelled_tasks"`
	MaxConcurrentTasks   int  `json:"max_concurrent_tasks"`
	TaskProcessorRunning bool `json:"task_processor_running"`
}

// handleTaskStats mirrors GET /tasks/stats.
//
//	@Summary		Task queue statistics
//	@Description	Minimum role: viewer.
//	@Tags			Task Management
//	@Produce		json
//	@Success		200	{object}	taskStatsResponse	"Queue statistics"
//	@Router			/tasks/stats [get]
func (s *Server) handleTaskStats(w http.ResponseWriter, r *http.Request) {
	counts, err := s.tasks.Store().StatusCounts(r.Context())
	if err != nil {
		slog.Error("task stats", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve task statistics")
		return
	}
	writeJSON(w, taskStatsResponse{
		PendingTasks:         counts[tasks.StatusPending],
		RunningTasks:         s.tasks.RunningCount(),
		CompletedTasks:       counts[tasks.StatusCompleted],
		FailedTasks:          counts[tasks.StatusFailed],
		CancelledTasks:       counts[tasks.StatusCancelled],
		MaxConcurrentTasks:   s.tasks.MaxConcurrent(),
		TaskProcessorRunning: s.tasks.ProcessorRunning(),
	})
}

// handleTaskDetails mirrors GET /tasks/{taskId}.
//
//	@Summary		Task details
//	@Description	Minimum role: viewer.
//	@Tags			Task Management
//	@Produce		json
//	@Param			taskId	path	string	true	"Task id"
//	@Success		200	{object}	tasks.Task	"The task"
//	@Failure		404	{object}	taskErrorBody	"Task not found"
//	@Router			/tasks/{taskId} [get]
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

// taskOutputResponse is GET /tasks/{taskId}/output's answer.
type taskOutputResponse struct {
	TaskID string              `json:"task_id"`
	Status string              `json:"status"`
	Output []tasks.OutputEntry `json:"output"`
}

// handleTaskOutput mirrors GET /tasks/{taskId}/output: the live in-memory
// buffer while the task runs, the persisted output afterwards.
//
//	@Summary		Task output
//	@Description	Minimum role: viewer. The live in-memory buffer while the task runs; the persisted output afterwards.
//	@Tags			Task Management
//	@Produce		json
//	@Param			taskId	path	string	true	"Task id"
//	@Success		200	{object}	taskOutputResponse	"Output entries"
//	@Failure		404	{object}	taskErrorBody	"Task not found"
//	@Router			/tasks/{taskId}/output [get]
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
	writeJSON(w, taskOutputResponse{
		TaskID: taskID,
		Status: task.Status,
		Output: output,
	})
}

// cancelTaskResponse is DELETE /tasks/{taskId}'s success answer.
type cancelTaskResponse struct {
	Success bool   `json:"success"`
	TaskID  string `json:"task_id"`
	Message string `json:"message"`
}

// cancelConflictError is DELETE /tasks/{taskId}'s 400 body (task already
// in a terminal state).
type cancelConflictError struct {
	Error         string `json:"error"`
	CurrentStatus string `json:"current_status"`
}

// handleCancelTask mirrors DELETE /tasks/{taskId}, extended per D-F: running
// tasks are cancellable too — the executor's children are killed and its
// cleanup runs; the task lands in cancelled with output preserved.
//
//	@Summary		Cancel a task
//	@Description	Minimum role: operator. Pending tasks are cancelled immediately. Running tasks are cancellable too (this agent's D-F extension over the Node reference): the executor's child processes are killed, its per-operation cleanup runs, and the task lands in cancelled with its output preserved. Tasks pending on a cancelled task are cancelled by dependency propagation, and cancelling a parent orchestration anchor cascades to its whole chain — pending children flip, running children get their contexts killed.
//	@Tags			Task Management
//	@Produce		json
//	@Param			taskId	path	string	true	"Task id"
//	@Success		200	{object}	cancelTaskResponse	"Cancelled (pending) or cancellation in progress (running)"
//	@Failure		400	{object}	cancelConflictError	"Task already in a terminal state"
//	@Failure		404	{object}	taskErrorBody	"Task not found"
//	@Router			/tasks/{taskId} [delete]
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
		if werr := json.NewEncoder(w).Encode(cancelConflictError{
			Error:         "Can only cancel pending or running tasks",
			CurrentStatus: notCancellable.Status,
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
	writeJSON(w, cancelTaskResponse{
		Success: true,
		TaskID:  taskID,
		Message: message,
	})
}

// clearCompletedTasksResponse is DELETE /tasks/completed's answer.
type clearCompletedTasksResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	DeletedCount int64  `json:"deleted_count"`
}

// handleClearCompletedTasks mirrors DELETE /tasks/completed: hard-deletes
// every task in a terminal state.
//
//	@Summary		Clear finished tasks
//	@Description	Minimum role: operator. Hard-deletes every completed, completed_with_errors, failed, and cancelled task immediately. Pending and running tasks are untouched.
//	@Tags			Task Management
//	@Produce		json
//	@Success		200	{object}	clearCompletedTasksResponse	"Finished tasks deleted"
//	@Router			/tasks/completed [delete]
func (s *Server) handleClearCompletedTasks(w http.ResponseWriter, r *http.Request) {
	deleted, err := s.tasks.Store().DeleteFinished(r.Context())
	if err != nil {
		slog.Error("clear completed tasks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to clear completed tasks")
		return
	}
	slog.Info("completed tasks cleared", "deleted_count", deleted,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, clearCompletedTasksResponse{
		Success:      true,
		Message:      "Deleted " + strconv.FormatInt(deleted, 10) + " completed/failed/cancelled tasks",
		DeletedCount: deleted,
	})
}
