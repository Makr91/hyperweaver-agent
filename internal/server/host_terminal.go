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

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/hostshell"
)

// Host terminal sessions — zoneweaver's /term family on this agent: a shell
// ON THE AGENT HOST ITSELF, running as the agent's own user. ADMIN-ONLY at
// every REST verb (the auth policy's /term prefix): a host shell is full
// host access. The WebSocket wire is the SSH terminal's exactly — raw text
// both ways plus {"type":"resize","cols","rows"} JSON control frames — so
// the UI reuses one xterm.js component. Sessions are in-memory: shells never
// survive an agent restart.

// termSession is one host terminal session.
type termSession struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"` // active | closed
	Shell        string    `json:"shell"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`

	person string
	shell  *hostshell.Shell
	link   terminalLink
	done   chan struct{}
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

func (s *termSessions) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[id]; ok {
		session.LastActivity = time.Now()
	}
}

// idleOf lists the live sessions the key createdBy started that no socket is attached to.
func (s *termSessions) idleOf(createdBy string) []*termSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	idle := []*termSession{}
	for _, session := range s.sessions {
		if session.CreatedBy == createdBy && session.shell != nil && !session.link.attached() {
			idle = append(idle, session)
		}
	}
	return idle
}

// close tears a session's shell down and marks it closed; ended is true the first time.
func (s *termSessions) close(id string) (session *termSession, ended bool) {
	s.mu.Lock()
	session, ok := s.sessions[id]
	var shell *hostshell.Shell
	if ok && session.shell != nil {
		shell = session.shell
		session.shell = nil
		session.Status = "closed"
		session.LastActivity = time.Now()
		close(session.done)
	}
	s.mu.Unlock()
	if shell != nil {
		shell.Close()
	}
	return session, shell != nil
}

// handleStartTermSession opens a host shell and mints its session (POST /api/term/start).
//
//	@Summary		Start a host terminal session
//	@Description	Minimum role: ADMIN (the host-terminal capability token — every /api/term REST verb is admin-only: a shell on the agent host as the agent's own user is full host access). Opens the shell at once (PowerShell/cmd via ConPTY on Windows, $SHELL login shell via a real PTY elsewhere) and answers the session, status active, created_by the calling key; connect a terminal at the /api/term/{sessionId} WebSocket. The shell lives until DELETE /api/term/sessions/{sessionId}/stop, the shell's own exit, the calling key's revocation or deletion while no socket is attached, or the agent's stop; a socket's close leaves it running, its last output kept for the next socket. session-started {kind: host_shell, id, machine_name: ""} goes to the person on the sessions topic of GET /api/events. Sessions are in-memory — an agent restart closes them all.
//	@Tags			Console
//	@Produce		json
//	@Success		200	{object}	termSession	"Session created, the shell open"
//	@Failure		500	"The shell could not be opened"
//	@Router			/api/term/start [post]
func (s *Server) handleStartTermSession(w http.ResponseWriter, r *http.Request) {
	id, err := randomID()
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to start terminal session")
		return
	}
	identity := auth.FromContext(r.Context())
	session := &termSession{
		ID:           id,
		Status:       "active",
		CreatedBy:    identity.Name,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		person:       s.personOf(identity),
		done:         make(chan struct{}),
	}
	shell, err := hostshell.Start(80, 24, session.link.output)
	if err != nil {
		slog.Warn("host terminal start failed", "session_id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to start terminal session: "+err.Error())
		return
	}
	session.shell = shell
	session.Shell = shell.Program()
	s.termSessions.put(session)
	go s.watchTermSession(session)
	slog.Info("host terminal session created", "session_id", id, "created_by", identity.Name)
	s.publishSession(eventSessionStarted, sessionKindHostShell, id, "", session.person)
	writeJSON(w, session)
}

func (s *Server) watchTermSession(session *termSession) {
	shell := session.shell
	_ = shell.Wait()
	session.link.output("\r\nTerminal session closed.\r\n")
	s.endTermSession(session.ID)
}

// handleListTermSessions mirrors GET /api/term/sessions.
//
//	@Summary		List host terminal sessions
//	@Description	Minimum role: admin. Every session the agent holds, newest first, each {id, status, shell, created_by, created_at, last_activity}, status active or closed; a person re-attaches to the active ones their own key started.
//	@Tags			Console
//	@Produce		json
//	@Success		200	{array}	termSession	"Sessions"
//	@Router			/api/term/sessions [get]
func (s *Server) handleListTermSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.termSessions.snapshot())
}

// handleTermSessionInfo mirrors GET /api/term/sessions/{sessionId}.
//
//	@Summary		Host terminal session information
//	@Description	Minimum role: admin.
//	@Tags			Console
//	@Produce		json
//	@Param			sessionId	path	string	true	"Terminal session ID"
//	@Success		200	{object}	termSession	"The session"
//	@Failure		404	"Terminal session not found"
//	@Router			/api/term/sessions/{sessionId} [get]
func (s *Server) handleTermSessionInfo(w http.ResponseWriter, r *http.Request) {
	session := s.termSessions.get(r.PathValue("sessionId"))
	if session == nil {
		taskError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	writeJSON(w, session)
}

// handleStopTermSession mirrors DELETE /api/term/sessions/{sessionId}/stop.
//
//	@Summary		Stop a host terminal session
//	@Description	Minimum role: admin. Closes the shell, marks the session closed and sends session-ended on the sessions topic to the person who started it, so the tab closes in every open browser.
//	@Tags			Console
//	@Produce		json
//	@Param			sessionId	path	string	true	"Terminal session ID"
//	@Success		200	{object}	successMessageResponse	"Session stopped"
//	@Failure		404	"Terminal session not found"
//	@Router			/api/term/sessions/{sessionId}/stop [delete]
func (s *Server) handleStopTermSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	if s.termSessions.get(id) == nil {
		taskError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	s.endTermSession(id)
	writeJSON(w, successMessageResponse{Success: true, Message: "Terminal session stopped."})
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

// handleTermSocket serves the WebSocket at /api/term/{sessionId}: attaches
// the socket to the running host shell and pipes it — the SSH socket's exact wire.
//
//	@Summary		Host terminal (WebSocket)
//	@Description	WEBSOCKET upgrade — authenticate with an UNSCOPED ?ticket= (GET /api/ws-ticket without ?machine= — the frozen cross-agent shape: host-level streams take ONLY an unscoped ticket; a machine-scoped ticket answers the same 401 as an invalid one); the session id itself is mintable only by an admin at POST /api/term/start. Attaches to the session's running shell: the last output the shell wrote, up to 256 KiB, is replayed first, then the live stream; a second socket on the same session takes the first one's place. Closing the socket leaves the shell running for the next socket. Wire = the SSH terminal's exactly: raw text frames both ways, {"type": "resize", "cols": N, "rows": N} JSON frames resize the PTY, "Terminal session closed." marks shell exit — one xterm.js component serves both terminals.
//	@Tags			Console
//	@Param			sessionId	path	string	true	"Terminal session ID"
//	@Param			ticket	query	string	true	"WebSocket upgrade ticket (GET /api/ws-ticket, UNSCOPED — no ?machine=)"
//	@Success		101	"Switching Protocols — the terminal begins"
//	@Failure		401	"Missing, invalid, or machine-scoped ticket"
//	@Failure		404	"Terminal session not found or already closed"
//	@Router			/api/term/{sessionId} [get]
func (s *Server) handleTermSocket(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.ticketScope(w, r)
	if !ok {
		return
	}
	if !requireScope(w, scope, "") {
		return
	}
	sessionID := r.PathValue("sessionId")
	session := s.termSessions.get(sessionID)
	if session == nil {
		taskError(w, http.StatusNotFound, "Terminal session not found")
		return
	}
	s.termSessions.mu.Lock()
	shell := session.shell
	s.termSessions.mu.Unlock()
	if shell == nil {
		taskError(w, http.StatusNotFound, "Terminal session is closed")
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
	go func() {
		select {
		case <-session.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	handle := session.link.attach(sendText)
	defer session.link.detach(handle)
	s.termSessions.touch(sessionID)

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
		s.termSessions.touch(sessionID)
	}
}
