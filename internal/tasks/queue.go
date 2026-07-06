package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

// tlog is this package's category logger (the Node agent's task logger:
// logging.categories.tasks overrides its level).
func tlog() *slog.Logger {
	return logging.Category("tasks")
}

// Executor runs one operation kind. Run must honor ctx cancellation — that is
// how running tasks are cancelled (D-F): the queue cancels the context (which
// kills any exec.CommandContext children) and then calls OnCancel for the
// operation's cleanup (e.g. a start executor force-powering-off the machine
// the killed vagrant left half-up, SHI's stop-during-up semantics).
type Executor struct {
	// Run performs the operation, streaming into out.
	Run func(ctx context.Context, task *Task, out *OutputWriter) error
	// OnCancel performs the operation's post-kill cleanup; nil when the kill
	// alone is clean.
	OnCancel func(task *Task, out *OutputWriter)
}

// OutputWriter is the executor-facing handle for one task's output stream.
type OutputWriter struct {
	manager *OutputManager
	taskID  string
}

// Write appends a chunk to the task's output ("stdout" or "stderr").
func (w *OutputWriter) Write(stream, data string) {
	w.manager.Write(w.taskID, stream, data)
}

// QueueConfig sizes the queue loop.
type QueueConfig struct {
	// PollInterval is the queue tick (the Node agent's hardcoded 2s, made
	// configurable per the design).
	PollInterval time.Duration
	// MaxConcurrent caps simultaneously running tasks.
	MaxConcurrent int
	// RetentionDays: finished tasks older than this are deleted by the
	// periodic cleanup (the Node agent's host_monitoring.retention.tasks).
	RetentionDays int
	// CleanupInterval is how often the retention cleanup runs — the Node
	// agent's CleanupService cadence (cleanup.interval).
	CleanupInterval time.Duration
}

// runningEntry tracks one in-flight task.
type runningEntry struct {
	cancel    context.CancelFunc
	cancelled bool
}

// Queue is the task processor: a poll loop that picks the highest-priority
// runnable pending task, guards operation categories, dispatches to the
// executor registry, and maintains parent-task aggregation.
type Queue struct {
	store     *Store
	output    *OutputManager
	cfg       QueueConfig
	executors map[string]Executor

	mu         sync.Mutex
	running    map[string]*runningEntry
	categories map[string]string // category → holding task id
	processing bool
	stopCh     chan struct{}
	loopDone   chan struct{}
	inflight   sync.WaitGroup
}

// NewQueue builds the queue. Executors are registered before Start.
func NewQueue(store *Store, output *OutputManager, cfg QueueConfig) *Queue {
	return &Queue{
		store:      store,
		output:     output,
		cfg:        cfg,
		executors:  map[string]Executor{},
		running:    map[string]*runningEntry{},
		categories: map[string]string{},
	}
}

// Register adds the executor for an operation. Called at wiring time, before
// Start.
func (q *Queue) Register(operation string, executor Executor) {
	q.executors[operation] = executor
}

// Store exposes the underlying task store (task creation by other
// subsystems, and the HTTP surface's queries).
func (q *Queue) Store() *Store {
	return q.store
}

// Output exposes the output manager (the HTTP output endpoint and the future
// task-output WebSocket).
func (q *Queue) Output() *OutputManager {
	return q.output
}

// Start recovers stale rows and launches the poll loop.
func (q *Queue) Start() {
	if stale, err := q.store.FailStaleRunning(context.Background()); err != nil {
		tlog().Error("task startup recovery failed", "error", err)
	} else if stale > 0 {
		tlog().Warn("failed tasks left running by a previous agent process", "count", stale)
	}

	q.mu.Lock()
	if q.processing {
		q.mu.Unlock()
		return
	}
	q.processing = true
	q.stopCh = make(chan struct{})
	q.loopDone = make(chan struct{})
	q.mu.Unlock()

	tlog().Info("task processor started",
		"poll_interval", q.cfg.PollInterval, "max_concurrent", q.cfg.MaxConcurrent)
	go q.loop()
}

// Stop halts the poll loop and cancels every running task, waiting bounded
// time for executors to unwind (they must honor ctx cancellation; the
// process is usually exiting right after).
func (q *Queue) Stop() {
	q.mu.Lock()
	if !q.processing {
		q.mu.Unlock()
		return
	}
	q.processing = false
	close(q.stopCh)
	for _, entry := range q.running {
		entry.cancelled = true
		entry.cancel()
	}
	q.mu.Unlock()

	<-q.loopDone

	done := make(chan struct{})
	go func() {
		q.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		tlog().Warn("task executors still unwinding at shutdown")
	}
	tlog().Info("task processor stopped")
}

// ProcessorRunning reports whether the poll loop is active (GET /tasks/stats).
func (q *Queue) ProcessorRunning() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.processing
}

// RunningCount is the number of in-flight tasks (GET /tasks running_count).
func (q *Queue) RunningCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.running)
}

// MaxConcurrent is the configured concurrency cap (GET /tasks/stats).
func (q *Queue) MaxConcurrent() int {
	return q.cfg.MaxConcurrent
}

// loop is the poll loop, plus the retention cleanup on its own slower tick.
func (q *Queue) loop() {
	defer close(q.loopDone)
	ticker := time.NewTicker(q.cfg.PollInterval)
	defer ticker.Stop()
	cleanup := time.NewTicker(q.cfg.CleanupInterval)
	defer cleanup.Stop()
	// The Node agent's CleanupService runs once at startup before its
	// interval schedule.
	q.cleanupOld()
	for {
		select {
		case <-q.stopCh:
			return
		case <-ticker.C:
			q.tick()
		case <-cleanup.C:
			q.cleanupOld()
		}
	}
}

// CleanupNow deletes finished tasks past the retention window and returns
// how many were removed — the retention cleanup's work, shared by the
// periodic tick and POST /database/cleanup.
func (q *Queue) CleanupNow(ctx context.Context) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -q.cfg.RetentionDays)
	return q.store.DeleteFinishedBefore(ctx, cutoff)
}

// cleanupOld runs CleanupNow on the periodic tick (the Node agent's
// cleanupOldTasks).
func (q *Queue) cleanupOld() {
	deleted, err := q.CleanupNow(context.Background())
	if err != nil {
		tlog().Error("task retention cleanup failed", "error", err)
		return
	}
	if deleted > 0 {
		tlog().Info("task retention cleanup", "deleted_count", deleted,
			"retention_days", q.cfg.RetentionDays)
	}
}

// tick processes one queue step: propagate dependency failures, then start
// the highest-priority runnable task unless capacity or its category lock
// blocks it (the Node agent's processNextTask).
func (q *Queue) tick() {
	q.mu.Lock()
	capacityFull := len(q.running) >= q.cfg.MaxConcurrent
	q.mu.Unlock()
	if capacityFull {
		return
	}

	// Queue-lifetime work, not request-scoped — Background is correct here.
	ctx := context.Background()

	parents, err := q.store.CancelDependents(ctx)
	if err != nil {
		tlog().Error("cancel dependent tasks", "error", err)
		return
	}
	for _, parentID := range parents {
		q.updateParentProgress(ctx, parentID)
	}

	task, err := q.store.NextPending(ctx)
	if err != nil {
		tlog().Error("pick next task", "error", err)
		return
	}
	if task == nil {
		return
	}

	category := OperationCategory(task.Operation)
	q.mu.Lock()
	if category != "" {
		if holder, locked := q.categories[category]; locked {
			q.mu.Unlock()
			tlog().Debug("task waiting for category lock",
				"task_id", task.ID, "operation", task.Operation,
				"category", category, "held_by", holder)
			return
		}
	}
	q.mu.Unlock()

	if err := q.store.MarkRunning(ctx, task.ID); err != nil {
		tlog().Error("mark task running", "task_id", task.ID, "error", err)
		return
	}

	runCtx, cancel := context.WithCancel(context.Background())
	q.mu.Lock()
	q.running[task.ID] = &runningEntry{cancel: cancel}
	if category != "" {
		q.categories[category] = task.ID
	}
	q.mu.Unlock()

	tlog().Info("task started", "task_id", task.ID,
		"operation", task.Operation, "machine", task.MachineName)

	q.inflight.Add(1)
	go func() {
		defer q.inflight.Done()
		q.executeAndHandle(runCtx, task, category)
	}()
}

// executeAndHandle dispatches one task and records its outcome (the Node
// agent's executeAndHandleTask).
func (q *Queue) executeAndHandle(ctx context.Context, task *Task, category string) {
	q.output.Create(task.ID)
	out := &OutputWriter{manager: q.output, taskID: task.ID}

	executor, known := q.executors[task.Operation]
	var runErr error
	if known {
		runErr = executor.Run(ctx, task, out)
	} else {
		runErr = fmt.Errorf("unknown operation: %s", task.Operation)
	}

	q.mu.Lock()
	entry := q.running[task.ID]
	cancelled := entry != nil && entry.cancelled
	q.mu.Unlock()

	status := StatusCompleted
	var errorMessage *string
	switch {
	case cancelled:
		status = StatusCancelled
		if known && executor.OnCancel != nil {
			executor.OnCancel(task, out)
		}
	case runErr != nil:
		status = StatusFailed
		msg := runErr.Error()
		errorMessage = &msg
	}

	// Bookkeeping must survive the run context being cancelled — that is
	// exactly the cancellation path.
	finishCtx := context.Background()

	// Successful tasks land at 100% unless the executor already reported
	// higher-fidelity progress.
	percent := -1.0
	var info json.RawMessage
	if status == StatusCompleted {
		if fresh, gerr := q.store.Get(finishCtx, task.ID); gerr == nil && fresh.ProgressPercent < 100 {
			percent = 100
			raw, merr := json.Marshal(map[string]string{
				"status":       StatusCompleted,
				"completed_at": time.Now().UTC().Format(time.RFC3339),
			})
			if merr == nil {
				info = raw
			}
		}
	}

	if err := q.store.Finish(finishCtx, task.ID, status, errorMessage, percent, info); err != nil {
		tlog().Error("record task outcome", "task_id", task.ID, "error", err)
	}
	q.output.Finalize(task.ID)

	q.mu.Lock()
	delete(q.running, task.ID)
	if category != "" && q.categories[category] == task.ID {
		delete(q.categories, category)
	}
	q.mu.Unlock()

	if task.ParentTaskID != nil {
		q.updateParentProgress(finishCtx, *task.ParentTaskID)
	}

	switch status {
	case StatusFailed:
		tlog().Error("task failed", "task_id", task.ID,
			"operation", task.Operation, "machine", task.MachineName, "error", runErr)
	case StatusCancelled:
		tlog().Info("task cancelled", "task_id", task.ID,
			"operation", task.Operation, "machine", task.MachineName)
	default:
		tlog().Info("task completed", "task_id", task.ID,
			"operation", task.Operation, "machine", task.MachineName)
	}
}
