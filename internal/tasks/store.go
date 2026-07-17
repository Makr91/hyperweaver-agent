package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrNotFound is returned when no task has the requested id.
var ErrNotFound = errors.New("task not found")

// Migrations is the tasks.sqlite schema, applied by db.Open via user_version
// tracking. Columns mirror the Node agent's tasks table; timestamps are
// fixed-width UTC text so lexicographic order is chronological order.
var Migrations = []string{
	`CREATE TABLE tasks (
		id               TEXT PRIMARY KEY,
		machine_name     TEXT NOT NULL,
		operation        TEXT NOT NULL,
		status           TEXT NOT NULL DEFAULT 'pending',
		priority         INTEGER NOT NULL DEFAULT 60,
		created_by       TEXT NOT NULL,
		depends_on       TEXT,
		parent_task_id   TEXT,
		error_message    TEXT,
		created_at       TEXT NOT NULL,
		started_at       TEXT,
		completed_at     TEXT,
		updated_at       TEXT NOT NULL,
		metadata         TEXT,
		progress_percent REAL NOT NULL DEFAULT 0,
		progress_info    TEXT,
		output           TEXT
	);
	CREATE INDEX task_status_priority_idx ON tasks (status, priority);
	CREATE INDEX idx_tasks_created_at ON tasks (created_at DESC);
	CREATE INDEX idx_tasks_updated_at ON tasks (updated_at DESC);
	CREATE INDEX idx_tasks_operation ON tasks (operation);
	CREATE INDEX idx_tasks_parent ON tasks (parent_task_id);`,
}

// timeLayout is the stored timestamp format: fixed-width (zero-padded
// nanoseconds) UTC, so string comparison in SQL matches time order —
// RFC3339Nano would trim trailing zeros and break that.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// Store persists tasks in tasks.sqlite.
type Store struct {
	db *sql.DB
}

// NewStore wraps an opened tasks database.
func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
}

const taskColumns = `id, machine_name, operation, status, priority, created_by,
	depends_on, parent_task_id, error_message, created_at, started_at,
	completed_at, updated_at, metadata, progress_percent, progress_info, output`

// listColumns is taskColumns with the output blob nulled: GET /tasks is the
// UI's polling list, and a provision run's output is hundreds of KB per row —
// megabytes per poll for data the list never renders (Mark's ruling
// 2026-07-07, the joint W1 fix). The detail endpoint, /tasks/{id}/output, and
// the WebSocket stream keep serving output in full.
const listColumns = `id, machine_name, operation, status, priority, created_by,
	depends_on, parent_task_id, error_message, created_at, started_at,
	completed_at, updated_at, metadata, progress_percent, progress_info,
	NULL AS output`

// scanTask reads one task row from any row scanner.
func scanTask(row interface{ Scan(...any) error }) (*Task, error) {
	var t Task
	var createdAt, updatedAt string
	var startedAt, completedAt, progressInfo sql.NullString
	err := row.Scan(&t.ID, &t.MachineName, &t.Operation, &t.Status, &t.Priority,
		&t.CreatedBy, &t.DependsOn, &t.ParentTaskID, &t.ErrorMessage,
		&createdAt, &startedAt, &completedAt, &updatedAt,
		&t.Metadata, &t.ProgressPercent, &progressInfo, &t.Output)
	if err != nil {
		return nil, err
	}

	if t.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("task %s: parse created_at: %w", t.ID, err)
	}
	if t.UpdatedAt, err = time.Parse(timeLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("task %s: parse updated_at: %w", t.ID, err)
	}
	if startedAt.Valid {
		parsed, perr := time.Parse(timeLayout, startedAt.String)
		if perr != nil {
			return nil, fmt.Errorf("task %s: parse started_at: %w", t.ID, perr)
		}
		t.StartedAt = &parsed
	}
	if completedAt.Valid {
		parsed, perr := time.Parse(timeLayout, completedAt.String)
		if perr != nil {
			return nil, fmt.Errorf("task %s: parse completed_at: %w", t.ID, perr)
		}
		t.CompletedAt = &parsed
	}
	if progressInfo.Valid {
		t.ProgressInfo = json.RawMessage(progressInfo.String)
	}
	return &t, nil
}

// Create inserts a task. Insertion is enqueueing — except for Parent anchors,
// which start in status running (never dispatched; child completions drive
// them, Node-agent semantics).
func (s *Store) Create(ctx context.Context, nt *NewTask) (*Task, error) {
	id, err := newTaskID()
	if err != nil {
		return nil, err
	}
	status := StatusPending
	var startedAt any
	now := formatTime(time.Now())
	if nt.Parent {
		status = StatusRunning
		startedAt = now
	}
	if nt.Prepared {
		status = StatusPrepared
	}
	priority := nt.Priority
	if priority == 0 {
		priority = PriorityMedium
	}

	_, err = s.db.ExecContext(ctx, `INSERT INTO tasks
		(id, machine_name, operation, status, priority, created_by,
		 depends_on, parent_task_id, metadata, created_at, started_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, nt.MachineName, nt.Operation, status, priority, nt.CreatedBy,
		nt.DependsOn, nt.ParentTaskID, nt.Metadata, now, startedAt, now)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, id)
}

// Get returns the task with the given id, or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (*Task, error) {
	t, err := scanTask(s.db.QueryRowContext(ctx,
		`SELECT `+taskColumns+` FROM tasks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// ListFilter selects and orders tasks (the Node agent's GET /tasks query
// parameters).
type ListFilter struct {
	Status       string
	MachineName  string
	Operation    string
	OperationNot string
	MinPriority  *int
	ParentTaskID string
	Since        *time.Time // updated_at >= — incremental refresh
	Sort         string     // whitelisted column; default created_at
	Order        string     // ASC | DESC; default DESC
	Limit        int        // default 50
}

// sortColumns whitelists user-supplied sort columns.
var sortColumns = map[string]bool{
	"created_at": true, "priority": true, "status": true, "machine_name": true,
	"operation": true, "started_at": true, "completed_at": true,
}

// where appends the filter's WHERE clause to query and returns the bind
// arguments. All values travel as placeholders; every SQL fragment written
// here is a compile-time literal (no user input ever concatenates into the
// query text).
func (f *ListFilter) where(query *strings.Builder) []any {
	clauses := []string{}
	args := []any{}
	if f.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, f.Status)
	}
	if f.MachineName != "" {
		clauses = append(clauses, "machine_name = ?")
		args = append(args, f.MachineName)
	}
	if f.Operation != "" {
		clauses = append(clauses, "operation = ?")
		args = append(args, f.Operation)
	}
	if f.OperationNot != "" {
		clauses = append(clauses, "operation != ?")
		args = append(args, f.OperationNot)
	}
	if f.MinPriority != nil {
		clauses = append(clauses, "priority >= ?")
		args = append(args, *f.MinPriority)
	}
	if f.ParentTaskID != "" {
		clauses = append(clauses, "parent_task_id = ?")
		args = append(args, f.ParentTaskID)
	}
	if f.Since != nil {
		clauses = append(clauses, "updated_at >= ?")
		args = append(args, formatTime(*f.Since))
	}
	if len(clauses) == 0 {
		return args
	}
	query.WriteString(" WHERE ")
	query.WriteString(strings.Join(clauses, " AND "))
	return args
}

// List returns tasks matching the filter. The ORDER BY column and direction
// are whitelist lookups, never raw input.
func (s *Store) List(ctx context.Context, f *ListFilter) ([]*Task, error) {
	sortColumn := "created_at"
	if sortColumns[f.Sort] {
		sortColumn = f.Sort
	}
	direction := "DESC"
	if strings.EqualFold(f.Order, "ASC") {
		direction = "ASC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}

	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(listColumns)
	query.WriteString(" FROM tasks")
	args := f.where(&query)
	query.WriteString(" ORDER BY ")
	query.WriteString(sortColumn)
	query.WriteString(" ")
	query.WriteString(direction)
	query.WriteString(" LIMIT ?")
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	list := []*Task{}
	for rows.Next() {
		t, serr := scanTask(rows)
		if serr != nil {
			return nil, serr
		}
		list = append(list, t)
	}
	return list, rows.Err()
}

// Count returns how many tasks match the filter (GET /tasks include_count).
func (s *Store) Count(ctx context.Context, f *ListFilter) (int, error) {
	var query strings.Builder
	query.WriteString("SELECT COUNT(*) FROM tasks")
	args := f.where(&query)
	var n int
	err := s.db.QueryRowContext(ctx, query.String(), args...).Scan(&n)
	return n, err
}

// StatusCounts returns per-status task totals (GET /tasks/stats).
func (s *Store) StatusCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM tasks GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	counts := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if serr := rows.Scan(&status, &n); serr != nil {
			return nil, serr
		}
		counts[status] = n
	}
	return counts, rows.Err()
}

// NextPending returns the highest-priority, oldest pending task whose
// dependency (if any) has completed, skipping machines with a task already
// in flight (one running task per machine — zoneweaver's per-zone rule, SHI's
// per-server ExecutorManager dedup; a stop must never race a running start).
// Skipped machines never head-of-line block: the pick moves on to the next
// runnable machine. Nil when the queue has nothing runnable.
func (s *Store) NextPending(ctx context.Context, busyMachines []string) (*Task, error) {
	var query strings.Builder
	query.WriteString(`SELECT ` + taskColumns + ` FROM tasks
		WHERE status = 'pending'
		  AND (depends_on IS NULL
		       OR depends_on IN (SELECT id FROM tasks WHERE status = 'completed'))`)
	args := []any{}
	if len(busyMachines) > 0 {
		query.WriteString(" AND machine_name NOT IN (?")
		query.WriteString(strings.Repeat(", ?", len(busyMachines)-1))
		query.WriteString(")")
		for _, name := range busyMachines {
			args = append(args, name)
		}
	}
	// rowid tiebreak: a chain created in one burst lands identical
	// created_at strings (clock-tick granularity), and without a stable
	// third key two eligible chain tasks pick in ARBITRARY order
	// (runtime-proven 2026-07-07: a provision child overtook the sync
	// children created microseconds earlier). rowid is insertion order.
	query.WriteString(" ORDER BY priority DESC, created_at ASC, rowid ASC LIMIT 1")
	t, err := scanTask(s.db.QueryRowContext(ctx, query.String(), args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

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

// ChildCounts aggregates a parent's children by outcome. Cancelled children
// count as failed (Node-agent aggregation rule).
type ChildCounts struct {
	Total     int
	Completed int
	Failed    int
}

// CountChildren tallies the children of a parent task.
func (s *Store) CountChildren(ctx context.Context, parentID string) (ChildCounts, error) {
	var c ChildCounts
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(status = 'completed'), 0),
		COALESCE(SUM(status IN ('failed', 'cancelled')), 0)
		FROM tasks WHERE parent_task_id = ?`, parentID).
		Scan(&c.Total, &c.Completed, &c.Failed)
	return c, err
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
