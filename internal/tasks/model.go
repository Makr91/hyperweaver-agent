// Package tasks implements the agent's task queue (Agent API v1, ported from
// the Node zoneweaver-agent's TaskQueue): SQLite-persisted tasks with
// priorities, single-predecessor dependency chains, parent-task progress
// aggregation, per-operation-category concurrency locks, live output
// streaming with debounced persistence, and operation-aware cancellation of
// pending AND running tasks (architecture D-F).
package tasks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Task statuses. completed_with_errors is a parent-task terminal state: some
// children failed, some completed (design §3; the Node agent buries this
// distinction in progress_info — here it is the status proper).
const (
	StatusPending             = "pending"
	StatusRunning             = "running"
	StatusCompleted           = "completed"
	StatusFailed              = "failed"
	StatusCancelled           = "cancelled"
	StatusCompletedWithErrors = "completed_with_errors"
)

// Task priorities (higher runs first), the Node agent's TaskPriority levels
// minus its redundant NORMAL alias.
const (
	PriorityCritical   = 100 // delete operations
	PriorityHigh       = 80  // stop operations
	PriorityMedium     = 60  // start/create operations
	PriorityService    = 50  // service operations
	PriorityLow        = 40  // restart, auto-started consoles
	PriorityBackground = 20  // discovery, periodic scans
)

// Task is one queue entry. JSON field names are the Agent API v1 Task schema.
type Task struct {
	ID              string          `json:"id"`
	MachineName     string          `json:"machine_name"`
	Operation       string          `json:"operation"`
	Status          string          `json:"status"`
	Priority        int             `json:"priority"`
	CreatedBy       string          `json:"created_by"`
	DependsOn       *string         `json:"depends_on"`
	ParentTaskID    *string         `json:"parent_task_id"`
	ErrorMessage    *string         `json:"error_message"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at"`
	CompletedAt     *time.Time      `json:"completed_at"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	Metadata        *string         `json:"metadata"`
	ProgressPercent float64         `json:"progress_percent"`
	ProgressInfo    json.RawMessage `json:"progress_info"`
	Output          *string         `json:"output"`
}

// NewTask describes a task to enqueue. Inserting the row IS enqueueing
// (Node-agent model); the queue's poll loop picks it up.
type NewTask struct {
	MachineName  string
	Operation    string
	Priority     int
	CreatedBy    string
	DependsOn    *string
	ParentTaskID *string
	Metadata     *string

	// Parent marks a progress-aggregation anchor: the task is created in
	// status running and never dispatched — child completions drive its
	// progress and final status.
	Parent bool
}

// newTaskID mints a random UUIDv4 (the Node agent's task id format).
func newTaskID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(raw)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32], nil
}
