package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

// taskColumns deliberately EXCLUDES the output column: task rows never carry
// output on the wire — Task.Output is ALWAYS null on the list AND the detail
// (Mark's 2026-07-07 list ruling extended whole by the converged task wire; a
// provision run's output is hundreds of KB per row). GET /tasks/{taskId}/output,
// the /tasks/{taskId}/stream WebSocket, and the OutputManager are the output
// channels; Store.GetOutput reads the column directly.
const taskColumns = `id, machine_name, operation, status, priority, created_by,
	depends_on, parent_task_id, error_message, created_at, started_at,
	completed_at, updated_at, metadata, progress_percent, progress_info`

// scanTask reads one task row from any row scanner.
func scanTask(row interface{ Scan(...any) error }) (*Task, error) {
	var t Task
	var createdAt, updatedAt string
	var startedAt, completedAt, metadata, progressInfo sql.NullString
	err := row.Scan(&t.ID, &t.MachineName, &t.Operation, &t.Status, &t.Priority,
		&t.CreatedBy, &t.DependsOn, &t.ParentTaskID, &t.ErrorMessage,
		&createdAt, &startedAt, &completedAt, &updatedAt,
		&metadata, &t.ProgressPercent, &progressInfo)
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
	if metadata.Valid && json.Valid([]byte(metadata.String)) {
		t.Metadata = json.RawMessage(metadata.String)
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

// sortColumns whitelists user-supplied sort columns: the VALUE (a
// compile-time literal) enters the query, never the user's string — the
// lookup key is only ever compared.
var sortColumns = map[string]string{
	"created_at": "created_at", "priority": "priority", "status": "status",
	"machine_name": "machine_name", "operation": "operation",
	"started_at": "started_at", "completed_at": "completed_at",
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
	if column, ok := sortColumns[f.Sort]; ok {
		sortColumn = column
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
	query.WriteString(taskColumns)
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
