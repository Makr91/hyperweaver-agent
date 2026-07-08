package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The WebSocket plane — the base's WsTicket + WebSocketHandler ported:
// GET /ws-ticket (authenticated) mints a short-lived unbound ticket, and
// every WebSocket upgrade requires it as ?ticket= (the auth middleware's
// header contract doesn't fit browser WebSocket clients). First consumer:
// GET /tasks/{taskId}/stream — replay + live task output + a final status
// frame, the UI's live task view.

// ticketTTL matches the base's 60-second window (connect + quick
// auto-reconnects; tickets are reusable within it, never consumed).
const ticketTTL = 60 * time.Second

// wsTickets is the in-memory ticket store (a restart just means the client
// fetches a fresh ticket — the base's model).
type wsTickets struct {
	mu      sync.Mutex
	tickets map[string]time.Time
}

func newWsTickets() *wsTickets {
	return &wsTickets{tickets: map[string]time.Time{}}
}

// Mint creates a ticket and sweeps expired ones (lazy — no background timer).
func (t *wsTickets) Mint() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	for existing, expires := range t.tickets {
		if now.After(expires) {
			delete(t.tickets, existing)
		}
	}
	t.tickets[ticket] = now.Add(ticketTTL)
	return ticket, nil
}

// Verify reports whether a ticket is present and unexpired (expired entries
// delete lazily; valid tickets stay reusable).
func (t *wsTickets) Verify(ticket string) bool {
	if ticket == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	expires, ok := t.tickets[ticket]
	if !ok {
		return false
	}
	if time.Now().After(expires) {
		delete(t.tickets, ticket)
		return false
	}
	return true
}

// handleWsTicket mints a WebSocket upgrade ticket (the base's GET /ws-ticket
// — operator role via the central policy's explicit /ws-ticket rule).
func (s *Server) handleWsTicket(w http.ResponseWriter, _ *http.Request) {
	ticket, err := s.wsTickets.Mint()
	if err != nil {
		slog.Error("mint ws ticket", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to mint ticket")
		return
	}
	writeJSON(w, map[string]any{"ticket": ticket})
}

// requireTicket gates a WebSocket upgrade on ?ticket= (the base's rule: the
// API-key middleware never sees upgrade requests from browsers). False =
// response already written.
func (s *Server) requireTicket(w http.ResponseWriter, r *http.Request) bool {
	if !s.wsTickets.Verify(r.URL.Query().Get("ticket")) {
		taskError(w, http.StatusUnauthorized, "Missing or invalid ticket — mint one via GET /ws-ticket")
		return false
	}
	return true
}

// taskFinished reports a terminal task status (completed_with_errors is a
// real status on this agent).
func taskFinished(status string) bool {
	switch status {
	case tasks.StatusCompleted, tasks.StatusFailed, tasks.StatusCancelled,
		tasks.StatusCompletedWithErrors:
		return true
	}
	return false
}

// outputFrame is the stream's per-chunk wire shape (the base's exact frames).
type outputFrame struct {
	Type      string `json:"type"`
	TaskID    string `json:"task_id"`
	Stream    string `json:"stream,omitempty"`
	Data      string `json:"data,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Status    string `json:"status,omitempty"`
}

// writeFrame sends one JSON frame with a write deadline.
func writeFrame(ctx context.Context, conn *websocket.Conn, frame *outputFrame) error {
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	return conn.Write(writeCtx, websocket.MessageText, raw)
}

// handleTaskStream serves GET /tasks/{taskId}/stream: replay the buffered (or
// persisted) output, then live entries, then a final status frame and close —
// the base's handleTaskStreamConnection.
func (s *Server) handleTaskStream(w http.ResponseWriter, r *http.Request) {
	if !s.requireTicket(w, r) {
		return
	}
	taskID := r.PathValue("taskId")
	task, err := s.tasks.Store().Get(r.Context(), taskID)
	if err != nil {
		taskError(w, http.StatusNotFound, "Task not found")
		return
	}
	replay, err := s.tasks.Output().GetOutput(r.Context(), taskID)
	if err != nil {
		slog.Error("task stream output fetch", "task_id", taskID, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to retrieve task output")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The ticket is the auth; agents live in a many-to-many mesh where
		// the browser Origin is not the boundary (the CORS model).
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		slog.Warn("task stream accept failed", "task_id", taskID, "error", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// The connection context ends when the client goes away: a read loop
	// (clients send nothing meaningful) surfaces the close.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		for {
			if _, _, rerr := conn.Read(ctx); rerr != nil {
				cancel()
				return
			}
		}
	}()

	for i := range replay {
		if werr := writeFrame(ctx, conn, &outputFrame{
			Type: "output", TaskID: taskID,
			Stream: replay[i].Stream, Data: replay[i].Data, Timestamp: replay[i].Timestamp,
		}); werr != nil {
			return
		}
	}

	if taskFinished(task.Status) {
		_ = writeFrame(ctx, conn, &outputFrame{Type: "status", TaskID: taskID, Status: task.Status})
		return
	}

	// Live phase: subscriber entries funnel through a channel so the
	// WebSocket has exactly one writer.
	entries := make(chan tasks.OutputEntry, 256)
	unsubscribe := s.tasks.Output().Subscribe(taskID, func(entry tasks.OutputEntry) {
		select {
		case entries <- entry:
		case <-ctx.Done():
		}
	})
	defer unsubscribe()

	// The task can finish between the status check and the subscribe — the
	// session would be gone and no finalize marker would ever arrive.
	if fresh, ferr := s.tasks.Store().Get(ctx, taskID); ferr == nil && taskFinished(fresh.Status) {
		_ = writeFrame(ctx, conn, &outputFrame{Type: "status", TaskID: taskID, Status: fresh.Status})
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-entries:
			if entry.Stream == "system" && entry.Data == "finalized" {
				status := tasks.StatusCompleted
				if final, gerr := s.tasks.Store().Get(ctx, taskID); gerr == nil {
					status = final.Status
				}
				_ = writeFrame(ctx, conn, &outputFrame{Type: "status", TaskID: taskID, Status: status})
				return
			}
			if werr := writeFrame(ctx, conn, &outputFrame{
				Type: "output", TaskID: taskID,
				Stream: entry.Stream, Data: entry.Data, Timestamp: entry.Timestamp,
			}); werr != nil {
				return
			}
		}
	}
}
