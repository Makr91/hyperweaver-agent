package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// MarkRunning transitions a task to running.
func (s *Store) MarkRunning(ctx context.Context, id string) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET status = 'running', started_at = ?, updated_at = ? WHERE id = ?`,
		now, now, id)
	return err
}

// Finish records a task's terminal state. progressInfo may be nil to leave
// the column untouched; progressPercent < 0 leaves the percentage untouched.
func (s *Store) Finish(ctx context.Context, id, status string, errorMessage *string, progressPercent float64, progressInfo json.RawMessage) error {
	now := formatTime(time.Now())
	var query strings.Builder
	query.WriteString("UPDATE tasks SET status = ?, error_message = ?, completed_at = ?, updated_at = ?")
	args := []any{status, errorMessage, now, now}
	if progressPercent >= 0 {
		query.WriteString(", progress_percent = ?")
		args = append(args, progressPercent)
	}
	if progressInfo != nil {
		query.WriteString(", progress_info = ?")
		args = append(args, string(progressInfo))
	}
	query.WriteString(" WHERE id = ?")
	args = append(args, id)
	_, err := s.db.ExecContext(ctx, query.String(), args...)
	return err
}

// UpdateProgress records live executor progress on a running task.
func (s *Store) UpdateProgress(ctx context.Context, id string, percent float64, info json.RawMessage) error {
	var infoValue any
	if info != nil {
		infoValue = string(info)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET progress_percent = ?, progress_info = ?, updated_at = ? WHERE id = ?`,
		percent, infoValue, formatTime(time.Now()), id)
	return err
}

// TransferProgress maps a byte transfer into ONE task step's existing
// progress window (converged, sync 2026-07-17 — both agents ship the
// identical task wire, no new endpoints): while bytes move, progress_percent
// maps received/total into [floor, ceil] and progress_info carries exactly
// {"status": "downloading"|"uploading", "received_bytes": <int>,
// "total_bytes": <int|null>} — received_bytes is bytes transferred so far in
// EITHER direction (uniform wire), total_bytes is the Content-Length (or
// known file size), JSON null when unknown. Throttle: an update at most every
// 1s OR every 1% of total, whichever comes first; Finish always emits the
// final state. Unknown totals (total <= 0) park the percent at the window
// floor — no fake percent — while received_bytes still streams. Progress
// never fails an operation (the taskProgress contract): failures log and
// swallow, and bookkeeping uses a background context so a cancelled task
// still records its last state.
type TransferProgress struct {
	store  *Store
	taskID string
	status string
	floor  float64
	ceil   float64
	total  int64

	received  int64
	lastEmit  time.Time
	lastBytes int64
	emitted   bool
}

// NewTransferProgress builds the emitter for one transfer step. floor/ceil
// are the step's EXISTING percent bounds; total <= 0 means unknown.
func NewTransferProgress(store *Store, taskID, status string, floor, ceil float64, total int64) *TransferProgress {
	return &TransferProgress{
		store:  store,
		taskID: taskID,
		status: status,
		floor:  floor,
		ceil:   ceil,
		total:  total,
	}
}

// Set records the absolute byte count and emits when the throttle allows.
// Monotonic: a chunk retry re-reporting from its own start never walks the
// wire backwards.
func (p *TransferProgress) Set(received int64) {
	if p == nil {
		return
	}
	if received <= p.received && p.emitted {
		return
	}
	if received > p.received {
		p.received = received
	}
	now := time.Now()
	due := !p.emitted || now.Sub(p.lastEmit) >= time.Second
	if !due && p.total > 0 {
		step := p.total / 100
		if step < 1 {
			step = 1
		}
		due = p.received-p.lastBytes >= step
	}
	if due {
		p.emit(now)
	}
}

// Finish always emits the final state — the completion update the throttle
// must never swallow.
func (p *TransferProgress) Finish() {
	if p == nil {
		return
	}
	p.emit(time.Now())
}

// emit writes one progress row: percent mapped into the window (parked at the
// floor when the total is unknown), progress_info in the converged shape.
func (p *TransferProgress) emit(now time.Time) {
	percent := p.floor
	var totalValue any
	if p.total > 0 {
		totalValue = p.total
		fraction := float64(p.received) / float64(p.total)
		if fraction > 1 {
			fraction = 1
		}
		percent = p.floor + (p.ceil-p.floor)*fraction
	}
	info, err := json.Marshal(map[string]any{
		"status":         p.status,
		"received_bytes": p.received,
		"total_bytes":    totalValue,
	})
	if err != nil {
		return
	}
	if uerr := p.store.UpdateProgress(context.Background(), p.taskID, percent, info); uerr != nil {
		tlog().Debug("transfer progress update failed", "task_id", p.taskID, "error", uerr)
	}
	p.emitted = true
	p.lastEmit = now
	p.lastBytes = p.received
}

// Reader wraps r so every byte read reports through Set. base offsets chunked
// transfers: chunk k's reader counts from k×chunk_size, so a retried chunk
// re-reports its own range instead of inflating the total.
func (p *TransferProgress) Reader(r io.Reader, base int64) io.Reader {
	return &transferReader{r: r, progress: p, base: base}
}

// transferReader is the counting reader behind TransferProgress.Reader.
type transferReader struct {
	r        io.Reader
	progress *TransferProgress
	base     int64
	offset   int64
}

func (t *transferReader) Read(b []byte) (int, error) {
	n, err := t.r.Read(b)
	if n > 0 {
		t.offset += int64(n)
		t.progress.Set(t.base + t.offset)
	}
	return n, err
}

// UpdateMetadata replaces a task's metadata document — zoneweaver's
// inter-child handoff: the storage child records _execution_output in its own
// metadata and the config child reads it through depends_on.
func (s *Store) UpdateMetadata(ctx context.Context, id, metadata string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET metadata = ?, updated_at = ? WHERE id = ?`,
		metadata, formatTime(time.Now()), id)
	if err != nil {
		return err
	}
	return requireTaskRow(res)
}

// requireTaskRow errors when an update matched nothing.
func requireTaskRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Requeue flips a prepared task to pending (the artifact-upload handshake's
// second half — the file has landed, the executor may run). False when the
// task was not in prepared state.
func (s *Store) Requeue(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE tasks
		SET status = 'pending', updated_at = ?
		WHERE id = ? AND status = 'prepared'`, formatTime(time.Now()), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetOutput persists the (JSON-serialized) output buffer — the output
// manager's debounced flush target.
func (s *Store) SetOutput(ctx context.Context, id, outputJSON string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE tasks SET output = ?, updated_at = ? WHERE id = ?`,
		outputJSON, formatTime(time.Now()), id)
	return err
}

// GetOutput returns the persisted output column ("" when never flushed).
func (s *Store) GetOutput(ctx context.Context, id string) (string, error) {
	var output sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT output FROM tasks WHERE id = ?`, id).Scan(&output)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return output.String, nil
}
