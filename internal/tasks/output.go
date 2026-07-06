package tasks

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// OutputEntry is one chunk of task output — the wire shape of the Node
// agent's TaskOutputManager buffer entries. Timestamp is Unix milliseconds.
type OutputEntry struct {
	Stream    string `json:"stream"`
	Data      string `json:"data"`
	Timestamp int64  `json:"timestamp"`
}

// OutputConfig controls buffering and persistence of task output.
type OutputConfig struct {
	// Enabled turns output capture on (default true); disabled tasks run
	// silently.
	Enabled bool
	// Mode is "full" (keep everything, default) or "circular" (cap the
	// buffer at CircularMaxLines, dropping the oldest).
	Mode string
	// CircularMaxLines caps the buffer in circular mode.
	CircularMaxLines int
	// FlushInterval debounces database writes: output lands in SQLite at
	// most once per interval plus once at finalize, never per chunk.
	FlushInterval time.Duration
	// PersistLogFile also writes a plain-text per-task log file at finalize.
	PersistLogFile bool
	// LogDirectory receives the per-task log files.
	LogDirectory string
}

// outputSession is one task's live buffer.
type outputSession struct {
	buffer      []OutputEntry
	subscribers map[int]func(OutputEntry)
	nextSubID   int
	flushTimer  *time.Timer
	totalSize   int
}

// OutputManager buffers running tasks' output in memory, notifies live
// subscribers (the future task-output WebSocket plugs in here), flushes to
// the database on a debounce, and writes optional log files at finalize —
// a port of the Node agent's TaskOutputManager.
type OutputManager struct {
	store *Store
	cfg   OutputConfig

	mu       sync.Mutex
	sessions map[string]*outputSession
}

// NewOutputManager builds the manager over the task store.
func NewOutputManager(store *Store, cfg OutputConfig) *OutputManager {
	return &OutputManager{
		store:    store,
		cfg:      cfg,
		sessions: map[string]*outputSession{},
	}
}

// Create opens an output session for a task about to run.
func (m *OutputManager) Create(taskID string) {
	if !m.cfg.Enabled {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[taskID]; exists {
		return
	}
	m.sessions[taskID] = &outputSession{subscribers: map[int]func(OutputEntry){}}
}

// Write appends a chunk to the task's buffer, notifies subscribers, and
// schedules the debounced database flush.
func (m *OutputManager) Write(taskID, stream, data string) {
	entry := OutputEntry{Stream: stream, Data: data, Timestamp: time.Now().UnixMilli()}

	m.mu.Lock()
	session, ok := m.sessions[taskID]
	if !ok {
		m.mu.Unlock()
		return
	}
	session.buffer = append(session.buffer, entry)
	session.totalSize += len(data)
	if m.cfg.Mode == "circular" && len(session.buffer) > m.cfg.CircularMaxLines {
		session.buffer = session.buffer[len(session.buffer)-m.cfg.CircularMaxLines:]
	}
	callbacks := subscriberList(session)
	if session.flushTimer == nil {
		session.flushTimer = time.AfterFunc(m.cfg.FlushInterval, func() {
			m.flush(taskID, true)
		})
	}
	m.mu.Unlock()

	for _, cb := range callbacks {
		cb(entry)
	}
}

// Subscribe registers a live-output callback and returns its unsubscribe
// function. Callbacks fire outside the manager lock.
func (m *OutputManager) Subscribe(taskID string, cb func(OutputEntry)) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[taskID]
	if !ok {
		return func() {}
	}
	id := session.nextSubID
	session.nextSubID++
	session.subscribers[id] = cb
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if s, still := m.sessions[taskID]; still {
			delete(s.subscribers, id)
		}
	}
}

// Finalize flushes the buffer to the database, writes the optional log file,
// notifies subscribers of completion, and drops the in-memory session.
func (m *OutputManager) Finalize(taskID string) {
	m.mu.Lock()
	session, ok := m.sessions[taskID]
	if !ok {
		m.mu.Unlock()
		return
	}
	if session.flushTimer != nil {
		session.flushTimer.Stop()
		session.flushTimer = nil
	}
	buffer := session.buffer
	callbacks := subscriberList(session)
	delete(m.sessions, taskID)
	m.mu.Unlock()

	m.persist(taskID, buffer)
	if m.cfg.PersistLogFile && len(buffer) > 0 {
		m.writeLogFile(taskID, buffer)
	}

	done := OutputEntry{Stream: "system", Data: "finalized", Timestamp: time.Now().UnixMilli()}
	for _, cb := range callbacks {
		cb(done)
	}
}

// GetOutput returns a task's output: the live buffer while it runs, the
// persisted column afterwards.
func (m *OutputManager) GetOutput(ctx context.Context, taskID string) ([]OutputEntry, error) {
	m.mu.Lock()
	if session, ok := m.sessions[taskID]; ok {
		out := make([]OutputEntry, len(session.buffer))
		copy(out, session.buffer)
		m.mu.Unlock()
		return out, nil
	}
	m.mu.Unlock()

	stored, err := m.store.GetOutput(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if stored == "" {
		return []OutputEntry{}, nil
	}
	var entries []OutputEntry
	if uerr := json.Unmarshal([]byte(stored), &entries); uerr != nil {
		return nil, uerr
	}
	return entries, nil
}

// flush writes the current buffer to the database. scheduled marks the
// debounce-timer path, which must clear the timer slot so the next Write can
// re-arm it.
func (m *OutputManager) flush(taskID string, scheduled bool) {
	m.mu.Lock()
	session, ok := m.sessions[taskID]
	if !ok {
		m.mu.Unlock()
		return
	}
	if scheduled {
		session.flushTimer = nil
	}
	buffer := make([]OutputEntry, len(session.buffer))
	copy(buffer, session.buffer)
	m.mu.Unlock()

	m.persist(taskID, buffer)
}

// persist serializes a buffer into the task row. Flushes are background
// work (debounce timers, finalization), never request-scoped.
func (m *OutputManager) persist(taskID string, buffer []OutputEntry) {
	if len(buffer) == 0 {
		return
	}
	raw, err := json.Marshal(buffer)
	if err != nil {
		tlog().Error("serialize task output", "task_id", taskID, "error", err)
		return
	}
	if serr := m.store.SetOutput(context.Background(), taskID, string(raw)); serr != nil {
		tlog().Error("flush task output to database", "task_id", taskID, "error", serr)
	}
}

// writeLogFile renders the buffer as a plain-text log (the Node agent's
// [STDOUT]/[STDERR] line format) into the configured directory.
func (m *OutputManager) writeLogFile(taskID string, buffer []OutputEntry) {
	dir, err := safepath.CleanAbs(m.cfg.LogDirectory)
	if err != nil {
		tlog().Error("task log directory invalid", "error", err)
		return
	}
	if merr := os.MkdirAll(dir, 0o700); merr != nil {
		tlog().Error("create task log directory", "dir", dir, "error", merr)
		return
	}
	path, err := safepath.Under(dir, taskID+".log")
	if err != nil {
		tlog().Error("task log path invalid", "task_id", taskID, "error", err)
		return
	}

	var b strings.Builder
	for _, entry := range buffer {
		prefix := "[STDOUT]"
		if entry.Stream == "stderr" {
			prefix = "[STDERR]"
		}
		b.WriteString(time.UnixMilli(entry.Timestamp).UTC().Format("2006-01-02T15:04:05.000Z"))
		b.WriteString(" ")
		b.WriteString(prefix)
		b.WriteString(" ")
		b.WriteString(entry.Data)
	}
	if err := safepath.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tlog().Error("write task log file", "task_id", taskID, "error", err)
	}
}

// subscriberList snapshots a session's callbacks for invocation outside the
// lock. Callers must hold m.mu.
func subscriberList(session *outputSession) []func(OutputEntry) {
	if len(session.subscribers) == 0 {
		return nil
	}
	callbacks := make([]func(OutputEntry), 0, len(session.subscribers))
	for _, cb := range session.subscribers {
		callbacks = append(callbacks, cb)
	}
	return callbacks
}
