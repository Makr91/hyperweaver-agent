package tasks

import (
	"context"
	"encoding/json"
	"math"
)

// Task cancellation and parent-task aggregation: the cancel flow (D-F) and
// the progress rollup that flips a parent anchor to its terminal state once
// every child is done.

// NotCancellableError reports a cancel request against a task already in a
// terminal state.
type NotCancellableError struct {
	// Status is the task's current (terminal) status.
	Status string
}

func (e *NotCancellableError) Error() string {
	return "task is " + e.Status
}

// Cancel cancels a task (DELETE /tasks/{id}). Pending tasks flip to
// cancelled immediately; running tasks get their context cancelled — the
// executor's children die, its OnCancel cleanup runs, and the task lands in
// cancelled with its output preserved (D-F). Returns true when the task was
// still running (cancellation is in progress rather than complete).
func (q *Queue) Cancel(ctx context.Context, id string) (wasRunning bool, err error) {
	task, err := q.store.Get(ctx, id)
	if err != nil {
		return false, err
	}

	for {
		switch task.Status {
		case StatusPending:
			done, cerr := q.store.CancelPending(ctx, id)
			if cerr != nil {
				return false, cerr
			}
			if done {
				if task.ParentTaskID != nil {
					q.updateParentProgress(ctx, *task.ParentTaskID)
				}
				return false, nil
			}
			// Lost the race with the queue loop — re-read and retry as the
			// state it moved to.
			task, err = q.store.Get(ctx, id)
			if err != nil {
				return false, err
			}

		case StatusRunning:
			q.mu.Lock()
			entry, inFlight := q.running[id]
			if inFlight {
				entry.cancelled = true
				entry.cancel()
			}
			q.mu.Unlock()
			if !inFlight {
				// Running in the database but not in this process: a parent
				// anchor (never dispatched — child completions drive it) or a
				// stale crash leftover; close it out directly. The anchor
				// leaves running FIRST so child completions no longer
				// recompute it, then the cascade takes its chain down —
				// cancelling an orchestration cancels the whole pipeline.
				if ferr := q.store.Finish(ctx, id, StatusCancelled, nil, -1, nil); ferr != nil {
					return false, ferr
				}
				q.cancelChildren(ctx, id)
				if task.ParentTaskID != nil {
					q.updateParentProgress(ctx, *task.ParentTaskID)
				}
				return false, nil
			}
			return true, nil

		default:
			return false, &NotCancellableError{Status: task.Status}
		}
	}
}

// cancelChildren cancels every unfinished child of a cancelled parent:
// pending children flip immediately, running ones get their contexts killed
// (D-F). Failures are logged — the parent is already terminal either way.
func (q *Queue) cancelChildren(ctx context.Context, parentID string) {
	for _, status := range []string{StatusPending, StatusRunning} {
		children, err := q.store.List(ctx, &ListFilter{
			ParentTaskID: parentID,
			Status:       status,
			Limit:        1000,
		})
		if err != nil {
			tlog().Error("list children for cascade cancel", "task_id", parentID, "error", err)
			continue
		}
		for _, child := range children {
			if _, cerr := q.Cancel(ctx, child.ID); cerr != nil {
				tlog().Warn("cascade-cancel child task", "task_id", child.ID, "error", cerr)
			}
		}
	}
}

// parentProgressInfo is a parent task's aggregated progress_info document.
type parentProgressInfo struct {
	CompletedTasks int    `json:"completed_tasks"`
	FailedTasks    int    `json:"failed_tasks"`
	TotalTasks     int    `json:"total_tasks"`
	Status         string `json:"status"`
}

// updateParentProgress recomputes a parent anchor's progress from its
// children and flips it to its terminal state once every child is done:
// failed (all children failed), completed_with_errors (some did), or
// completed.
func (q *Queue) updateParentProgress(ctx context.Context, parentID string) {
	parent, err := q.store.Get(ctx, parentID)
	if err != nil || parent.Status != StatusRunning {
		return
	}
	counts, err := q.store.CountChildren(ctx, parentID)
	if err != nil {
		tlog().Error("count parent task children", "task_id", parentID, "error", err)
		return
	}

	done := counts.Completed + counts.Failed
	percent := 0.0
	if counts.Total > 0 {
		percent = math.Round(float64(done) / float64(counts.Total) * 100)
	}

	status := StatusRunning
	if counts.Total > 0 && done == counts.Total {
		switch {
		case counts.Failed == counts.Total:
			status = StatusFailed
		case counts.Failed > 0:
			status = StatusCompletedWithErrors
		default:
			status = StatusCompleted
		}
	}

	info, err := json.Marshal(parentProgressInfo{
		CompletedTasks: counts.Completed,
		FailedTasks:    counts.Failed,
		TotalTasks:     counts.Total,
		Status:         status,
	})
	if err != nil {
		tlog().Error("serialize parent progress", "task_id", parentID, "error", err)
		return
	}

	if status == StatusRunning {
		if uerr := q.store.UpdateProgress(ctx, parentID, percent, info); uerr != nil {
			tlog().Error("update parent task progress", "task_id", parentID, "error", uerr)
		}
		return
	}
	if ferr := q.store.Finish(ctx, parentID, status, nil, percent, info); ferr != nil {
		tlog().Error("finish parent task", "task_id", parentID, "error", ferr)
	}
}
