package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Makr91/hyperweaver-agent/internal/hostshell"
)

// Host terminal sessions — zoneweaver's /term family on this agent: a shell
// ON THE AGENT HOST ITSELF, running as the agent's own user. ADMIN-ONLY at
// every REST verb (the auth policy's /term prefix): a host shell is full
// host access. The WebSocket wire is the SSH terminal's exactly — raw text
// both ways plus {"type":"resize","cols","rows"} JSON control frames — so
// the UI reuses one xterm.js component. Sessions are in-memory like SSH
// sessions: shells never survive an agent restart.

// termSession is one host terminal session.
type termSession struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"` // connecting | active | closed | failed
	Shell        string    `json:"shell"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`

	shell *hostshell.Shell
}

// termSessions is the in-memory session store.
type termSessions struct {
	mu       sync.Mutex
	sessions map[string]*termSession
}

func newTermSessions() *termSessions {
	return &termSessions{sessions: map[string]*termSession{}}
}

func (s *termSessions) get(id string) *termSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

func (s *termSessions) put(session *termSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

// snapshot lists sessions newest-first.
func (s *termSessions) snapshot() []*termSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]*termSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		list = append(list, session)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list
}

func (s *termSessions) setStatus(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[id]; ok {
		session.Status = status
		session.LastActivity = time.Now()
	}
}

// close tears a session's shell down and marks it closed.
func (s *termSessions) close(id string) bool {
	s.mu.Lock()
	session, ok := s.sessions[id]
	var shell *hostshell.Shell
	if ok {
		shell = session.shell
		session.shell = nil
		session.Status = "closed"
		session.LastActivity = time.Now()
	}
	s.mu.Unlock()
	if shell != nil {
		shell.Close()
	}
	return ok
}

// handleStartTermSession mints a host terminal session (POST /term/start);
// the shell itself opens when the WebSocket connects.
//
//	@Summary		Start a host terminal session
//	@Description	Minimum role: ADMIN (the host-terminal capability token — every /term REST verb is admin-only: a shell on the agent host as the agent's own user is full host access). Mints a session; connect the terminal at the /term/{sessionId} WebSocket, where the shell actually opens (PowerShell/cmd via ConPTY on Windows, $SHELL login shell via a real PTY elsewhere). Sessions are in-memory — an agent restart closes them all.
//	@Tags			Console
//	@Produce		json
//	@Success		200	{object}	termSession	"Session created"
//	@Router			/term/start [post]
func (s *Server) handleStartTermSession(w http.ResponseWriter, _ *http.Request) {
	id, err := randomID()
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to start terminal session")
		return
	}
	session := &termSession{
		ID:           id,
		Status:       "connecting",
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	s.termSessions.put(session)
	slog.Info("host terminal session created", "session_id", id)
	writeJSON(w, session)
}

// handleListTermSessions mirrors GET /term/sessions.
//
//	@Summary		List host terminal sessions
//	@Description	Minimum role: admin. Newest first.
//	@Tags			Console
//	@Produce		json
//	@Success		200	{array}	termSession	"Sessions"
//	@Router			/term/sessions [get]
func (s *Server) handleListTermSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.termSessions.snapshot())
}

// handleTermSessionInfo mirrors GET /term/sessions/{sessionId}.
//
//	@Summary		Host terminal session information
//	@Description	Minimum role: admin.
//	@Tags			Console
//	@Produce		json
//	@Param			sessionId	path	string	true	"Terminal session ID"
//	@Success		200	{object}	termSession	"The session"
//	@Failure		404	"Terminal session not found"
//	@Router			/term/sessions/{sessionId} [get]
func (s *Server) handleTermSessionInfo(w http.ResponseWriter, r *http.Request) {
	session := s.termSessions.get(r.PathValue("sessionId"))
	if session == nil {
		taskError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	writeJSON(w, session)
}

// handleStopTermSession mirrors DELETE /term/sessions/{sessionId}/stop.
//
//	@Summary		Stop a host terminal session
//	@Description	Minimum role: admin. Closes the shell and marks the session closed.
//	@Tags			Console
//	@Produce		json
//	@Param			sessionId	path	string	true	"Terminal session ID"
//	@Success		200	{object}	map[string]interface{}	"Session stopped"
//	@Failure		404	"Terminal session not found"
//	@Router			/term/sessions/{sessionId}/stop [delete]
func (s *Server) handleStopTermSession(w http.ResponseWriter, r *http.Request) {
	if !s.termSessions.close(r.PathValue("sessionId")) {
		taskError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	writeJSON(w, map[string]any{"success": true, "message": "Terminal session stopped."})
}

// parseResizeFrame recognizes a terminal resize control frame: bare JSON
// {"type":"resize","cols":N,"rows":N}, or the same JSON behind a leading NUL
// byte — zoneweaver's host-terminal framing (its footer terminal sends
// \x00-prefixed control frames; accepting both keeps one UI component honest
// against both agents). Anything else is raw terminal input.
func parseResizeFrame(data []byte) (cols, rows int, ok bool) {
	if len(data) > 0 && data[0] == 0 {
		data = data[1:]
	}
	var control terminalControl
	if err := json.Unmarshal(data, &control); err != nil {
		return 0, 0, false
	}
	if control.Type != "resize" || control.Cols <= 0 || control.Rows <= 0 {
		return 0, 0, false
	}
	return control.Cols, control.Rows, true
}

// handleTermSocket serves the WebSocket at /term/{sessionId}: opens the host
// shell and pipes it — the SSH socket's exact wire.
func (s *Server) handleTermSocket(w http.ResponseWriter, r *http.Request) {
	if !s.requireTicket(w, r) {
		return
	}
	sessionID := r.PathValue("sessionId")
	session := s.termSessions.get(sessionID)
	if session == nil {
		taskError(w, http.StatusNotFound, "Terminal session not found")
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		slog.Warn("terminal socket accept failed", "session_id", sessionID, "error", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sendText := func(text string) {
		writeCtx, done := context.WithTimeout(ctx, 10*time.Second)
		defer done()
		if werr := conn.Write(writeCtx, websocket.MessageText, []byte(text)); werr != nil {
			cancel()
		}
	}

	shell, err := hostshell.Start(80, 24, sendText)
	if err != nil {
		slog.Warn("host terminal start failed", "session_id", sessionID, "error", err)
		s.termSessions.setStatus(sessionID, "failed")
		sendText("Terminal error: " + err.Error() + "\r\n")
		return
	}
	s.termSessions.mu.Lock()
	session.shell = shell
	session.Shell = shell.Program()
	session.Status = "active"
	session.LastActivity = time.Now()
	s.termSessions.mu.Unlock()
	defer s.termSessions.close(sessionID)

	// Shell exit ends the connection.
	go func() {
		_ = shell.Wait()
		sendText("\r\nTerminal session closed.\r\n")
		cancel()
	}()

	// Client input loop: resize control frames (bare or NUL-prefixed JSON) or
	// raw terminal bytes.
	for {
		_, data, rerr := conn.Read(ctx)
		if rerr != nil {
			return
		}
		if cols, rows, isResize := parseResizeFrame(data); isResize {
			if werr := shell.Resize(cols, rows); werr != nil {
				slog.Debug("host terminal resize failed", "session_id", sessionID, "error", werr)
			}
			continue
		}
		if werr := shell.Write(string(data)); werr != nil {
			return
		}
	}
}
