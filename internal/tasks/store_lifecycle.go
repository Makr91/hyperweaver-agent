package tasks

import (
	"context"
	"database/sql"
	"time"
)

// CancelDependents cancels every pending task whose dependency failed or was
// cancelled, and returns the distinct parent-task ids of the cancelled rows
// so the caller can recompute their aggregation.
func (s *Store) CancelDependents(ctx context.Context) ([]string, error) {
	now := formatTime(time.Now())
	rows, err := s.db.QueryContext(ctx, `UPDATE tasks
		SET status = 'cancelled', error_message = 'Dependency failed',
		    completed_at = ?, updated_at = ?
		WHERE status = 'pending'
		  AND depends_on IN (SELECT id FROM tasks WHERE status IN ('failed', 'cancelled'))
		RETURNING parent_task_id`, now, now)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	seen := map[string]bool{}
	parents := []string{}
	for rows.Next() {
		var parent sql.NullString
		if serr := rows.Scan(&parent); serr != nil {
			return nil, serr
		}
		if parent.Valid && !seen[parent.String] {
			seen[parent.String] = true
			parents = append(parents, parent.String)
		}
	}
	return parents, rows.Err()
}

// CancelPending cancels a still-pending task (the DELETE /tasks/{id} fast
// path). False when the task was no longer pending by the time of the update.
func (s *Store) CancelPending(ctx context.Context, id string) (bool, error) {
	now := formatTime(time.Now())
	res, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET status = 'cancelled', completed_at = ?, updated_at = ?
		WHERE id = ? AND status = 'pending'`, now, now, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteFinished hard-deletes all completed, failed, and cancelled tasks
// (DELETE /tasks/completed) and returns how many were removed.
func (s *Store) DeleteFinished(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tasks
		WHERE status IN ('completed', 'completed_with_errors', 'failed', 'cancelled')`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteFinishedBefore removes finished tasks created before cutoff — the
// Node agent's retention-based cleanupOldTasks.
func (s *Store) DeleteFinishedBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tasks
		WHERE status IN ('completed', 'completed_with_errors', 'failed', 'cancelled')
		  AND created_at < ?`, formatTime(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CancelAllPending cancels every pending task — startup recovery's second
// half (Mark's ruling 2026-07-07, default behavior): a queued operation from
// a previous agent run must not fire on boot (yesterday's pending stop taking
// a machine down at startup). tasks.resume_pending_on_start re-enables the
// resumable queue.
func (s *Store) CancelAllPending(ctx context.Context) (int64, error) {
	now := formatTime(time.Now())
	// prepared rows cancel too: an upload handshake cannot survive a restart.
	res, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET status = 'cancelled',
		    error_message = 'Agent restarted before task ran',
		    completed_at = ?, updated_at = ?
		WHERE status IN ('pending', 'prepared')`, now, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FailStaleRunning marks tasks still recorded as running as failed — startup
// recovery: a task can only be running while an agent process is, so any
// running row at boot is a leftover from a previous process.
func (s *Store) FailStaleRunning(ctx context.Context) (int64, error) {
	now := formatTime(time.Now())
	res, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET status = 'failed',
		    error_message = 'Agent restarted while task was running',
		    completed_at = ?, updated_at = ?
		WHERE status = 'running'`, now, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
