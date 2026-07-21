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

// ticketTTL matches the base's 60-second window (connect + quick
// auto-reconnects; tickets are reusable within it, never consumed).
const ticketTTL = 60 * time.Second

type wsTicket struct {
	expires time.Time
	machine string
}

// wsTickets is the in-memory ticket store (a restart just means the client
// fetches a fresh ticket — the base's model).
type wsTickets struct {
	mu      sync.Mutex
	tickets map[string]wsTicket
}

func newWsTickets() *wsTickets {
	return &wsTickets{tickets: map[string]wsTicket{}}
}

func (t *wsTickets) Mint(machine string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()
	for existing, entry := range t.tickets {
		if now.After(entry.expires) {
			delete(t.tickets, existing)
		}
	}
	t.tickets[ticket] = wsTicket{expires: now.Add(ticketTTL), machine: machine}
	return ticket, nil
}

func (t *wsTickets) Lookup(ticket string) (machine string, ok bool) {
	if ticket == "" {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.tickets[ticket]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expires) {
		delete(t.tickets, ticket)
		return "", false
	}
	return entry.machine, true
}

// wsTicketResponse is GET /ws-ticket's answer.
type wsTicketResponse struct {
	// 64 hex chars, valid 60 seconds
	Ticket string `json:"ticket"`
}

// handleWsTicket mints a WebSocket upgrade ticket (the base's GET /ws-ticket
// — operator role via the central policy's explicit /ws-ticket rule).
//
//	@Summary		Mint a WebSocket upgrade ticket
//	@Description	Minimum role: operator. A short-lived (60s) ticket appended as ?ticket= to every WebSocket upgrade URL. Reusable within its lifetime; fetch a fresh one before each connect or reconnect. MACHINE SCOPE (the frozen cross-agent shape): ?machine={name} binds the ticket to that machine name (verbatim string, no existence check — the upgrade validates). Machine streams (VNC websockify, RDP bridge, machine SSH terminals, machine-task streams) accept ONLY a scoped ticket whose machine matches the target; host-level streams (the /term host shell, task streams of system/artifact/filesystem tasks) accept ONLY an unscoped ticket; any mismatch answers the same 401 as an invalid ticket.
//	@Tags			Console
//	@Produce		json
//	@Param			machine	query	string	false	"Bind the ticket to this machine name — required for machine console/stream upgrades; omit for host-level streams"
//	@Success		200	{object}	wsTicketResponse	"Ticket minted"
//	@Router			/ws-ticket [get]
func (s *Server) handleWsTicket(w http.ResponseWriter, r *http.Request) {
	ticket, err := s.wsTickets.Mint(r.URL.Query().Get("machine"))
	if err != nil {
		slog.Error("mint ws ticket", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to mint ticket")
		return
	}
	writeJSON(w, wsTicketResponse{Ticket: ticket})
}

const ticketRefusal = "Missing or invalid ticket — mint one via GET /ws-ticket"

func (s *Server) ticketScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	scope, ok := s.wsTickets.Lookup(r.URL.Query().Get("ticket"))
	if !ok {
		taskError(w, http.StatusUnauthorized, ticketRefusal)
		return "", false
	}
	return scope, true
}

func requireScope(w http.ResponseWriter, scope, want string) bool {
	if scope != want {
		taskError(w, http.StatusUnauthorized, ticketRefusal)
		return false
	}
	return true
}

func hostLevelTaskMachine(name string) bool {
	switch name {
	case "system", "artifact", "filesystem":
		return true
	}
	return false
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
//
//	@Summary		Live task output stream (WebSocket)
//	@Description	WEBSOCKET upgrade — authenticate with ?ticket= (GET /ws-ticket), not API-key headers. Ticket scope (the frozen cross-agent shape): a machine task's stream requires a ticket minted with ?machine= matching the task's machine_name; a host-level task's stream (machine_name "system", "artifact", or "filesystem") requires an UNSCOPED ticket — any mismatch answers the same 401 as an invalid ticket. Replays the task's buffered (or persisted) output as {type: "output", task_id, stream, data, timestamp} frames, streams live entries while the task runs, then sends {type: "status", task_id, status} and closes. Already-finished tasks get the full replay plus the status frame immediately.
//	@Tags			Console
//	@Param			taskId	path	string	true	"Task id"	format(uuid)
//	@Param			ticket	query	string	true	"WebSocket upgrade ticket (GET /ws-ticket) — scope must match the task (machine-scoped for machine tasks, unscoped for host-level tasks)"
//	@Success		101	"Switching Protocols — the stream begins"
//	@Failure		401	"Missing, invalid, or wrong-scope ticket"
//	@Failure		404	"Task not found"
//	@Router			/tasks/{taskId}/stream [get]
func (s *Server) handleTaskStream(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.ticketScope(w, r)
	if !ok {
		return
	}
	taskID := r.PathValue("taskId")
	task, err := s.tasks.Store().Get(r.Context(), taskID)
	if err != nil {
		taskError(w, http.StatusNotFound, "Task not found")
		return
	}
	want := task.MachineName
	if hostLevelTaskMachine(task.MachineName) {
		want = ""
	}
	if !requireScope(w, scope, want) {
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
