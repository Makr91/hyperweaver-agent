package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
)

// SSH terminal sessions — the base's SSHTerminal family on this agent's
// transport: POST /machines/{name}/ssh/start mints a session, the WebSocket
// at /ssh/{sessionId}?ticket=... opens the interactive shell. The shell
// prefers the provisioning NAT ssh port-forward (the pipeline's transport,
// immune to guest network reconfiguration) and falls back to the document's
// control IP — resolveTransport's exact ladder. Sessions are in-memory:
// shells never survive an agent restart (the base marks them all closed at
// startup for the same reason).

// sshSession is one terminal session (the base's SSHSession row shape).
type sshSession struct {
	ID           string    `json:"id"`
	MachineName  string    `json:"machine_name"`
	Status       string    `json:"status"` // connecting | active | closed | failed
	SSHHost      string    `json:"ssh_host"`
	SSHPort      int       `json:"ssh_port"`
	SSHUsername  string    `json:"ssh_username"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`

	shell *sshrun.Shell
}

// sshSessions is the in-memory session store.
type sshSessions struct {
	mu       sync.Mutex
	sessions map[string]*sshSession
}

func newSSHSessions() *sshSessions {
	return &sshSessions{sessions: map[string]*sshSession{}}
}

func (s *sshSessions) get(id string) *sshSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

func (s *sshSessions) put(session *sshSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
}

// snapshot lists sessions newest-first (the base's ordering).
func (s *sshSessions) snapshot() []*sshSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := make([]*sshSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		list = append(list, session)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list
}

// setStatus updates a session's lifecycle state.
func (s *sshSessions) setStatus(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[id]; ok {
		session.Status = status
		session.LastActivity = time.Now()
	}
}

// close tears a session's shell down and marks it closed.
func (s *sshSessions) close(id string) bool {
	s.mu.Lock()
	session, ok := s.sessions[id]
	var shell *sshrun.Shell
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

// randomID mints a session id (32 hex chars).
func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// sshTransport resolves the shell's target: the NAT ssh forward first
// (immune to guest network reconfiguration), the guest agent's live IP
// second (the QGA channel's truth), the document's control IP last
// (resolveTransport's ladder plus the live-truth rung).
func (s *Server) sshTransport(ctx context.Context, machine *machines.Machine,
	config machines.MachineConfig,
) (host string, port int) {
	if forwardPort := machines.FindSSHForward(ctx, machine); forwardPort > 0 {
		return "127.0.0.1", forwardPort
	}
	if ip := s.guestAgentIP(ctx, machine); ip != "" {
		return ip, 22
	}
	if ip := machines.ExtractControlIP(config.List("networks")); ip != "" {
		return ip, 22
	}
	return "", 0
}

// handleStartSSHSession mints an SSH terminal session (the base's POST
// /machines/{name}/ssh/start — each call is an independent session).
func (s *Server) handleStartSSHSession(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return
	}
	config := machines.ParseConfiguration(machine)
	credentials := machines.ExtractCredentials(config.Section("settings"))
	if credentials.Username == "" {
		taskError(w, http.StatusBadRequest,
			"SSH credentials not configured. Set settings.vagrant_user in the machine configuration.")
		return
	}
	host, port := s.sshTransport(r.Context(), machine, config)
	if host == "" {
		taskError(w, http.StatusBadRequest,
			"No SSH transport: machine has no NAT ssh port-forward, no guest-agent-reported IP, and no control IP in networks[] (set is_control: true on one network)")
		return
	}

	id, err := randomID()
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to start SSH session")
		return
	}
	session := &sshSession{
		ID:           id,
		MachineName:  machine.Name,
		Status:       "connecting",
		SSHHost:      host,
		SSHPort:      port,
		SSHUsername:  credentials.Username,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}
	s.sshSessions.put(session)
	slog.Info("ssh terminal session created", "session_id", id,
		"machine", machine.Name, "host", host, "port", port)
	writeJSON(w, session)
}

// handleListSSHSessions mirrors GET /ssh/sessions.
func (s *Server) handleListSSHSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.sshSessions.snapshot())
}

// handleSSHSessionInfo mirrors GET /ssh/sessions/{sessionId}.
func (s *Server) handleSSHSessionInfo(w http.ResponseWriter, r *http.Request) {
	session := s.sshSessions.get(r.PathValue("sessionId"))
	if session == nil {
		taskError(w, http.StatusNotFound, "SSH session not found")
		return
	}
	writeJSON(w, session)
}

// handleStopSSHSession mirrors DELETE /ssh/sessions/{sessionId}/stop.
func (s *Server) handleStopSSHSession(w http.ResponseWriter, r *http.Request) {
	if !s.sshSessions.close(r.PathValue("sessionId")) {
		taskError(w, http.StatusNotFound, "SSH session not found")
		return
	}
	writeJSON(w, map[string]any{"success": true, "message": "SSH session stopped."})
}

// terminalControl is the client → shell control frame (the base's resize
// message; anything non-JSON is raw terminal input).
type terminalControl struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// handleSSHSocket serves the WebSocket at /ssh/{sessionId}: dial, shell,
// bidirectional piping, resize control frames — the base's
// handleSSHConnection + setupSSHPiping.
func (s *Server) handleSSHSocket(w http.ResponseWriter, r *http.Request) {
	if !s.requireTicket(w, r) {
		return
	}
	sessionID := r.PathValue("sessionId")
	session := s.sshSessions.get(sessionID)
	if session == nil {
		taskError(w, http.StatusNotFound, "SSH session not found")
		return
	}
	machine, err := s.machines.Get(r.Context(), session.MachineName)
	if err != nil {
		taskError(w, http.StatusNotFound, "Machine not found")
		return
	}
	config := machines.ParseConfiguration(machine)
	credentials := machines.ExtractCredentials(config.Section("settings"))
	basePath := ""
	if machine.Home != nil {
		basePath = *machine.Home
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		slog.Warn("ssh socket accept failed", "session_id", sessionID, "error", err)
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

	sendText("Connecting to SSH...\r\n")
	connectCtx, connectCancel := context.WithTimeout(ctx, 20*time.Second)
	shell, err := sshrun.StartShell(connectCtx, session.SSHHost, session.SSHPort,
		sshrun.Credentials{
			Username:   credentials.Username,
			Password:   credentials.Password,
			SSHKeyPath: credentials.SSHKeyPath,
		},
		basePath, s.cfg.ProvisionKeyPath(), 80, 24, sendText)
	connectCancel()
	if err != nil {
		slog.Warn("ssh terminal connect failed", "session_id", sessionID, "error", err)
		s.sshSessions.setStatus(sessionID, "failed")
		sendText("SSH connection error: " + err.Error() + "\r\n")
		return
	}
	s.sshSessions.mu.Lock()
	session.shell = shell
	session.Status = "active"
	session.LastActivity = time.Now()
	s.sshSessions.mu.Unlock()
	defer s.sshSessions.close(sessionID)

	// Remote shell exit ends the connection.
	go func() {
		_ = shell.Wait()
		sendText("\r\nSSH connection closed.\r\n")
		cancel()
	}()

	// Client input loop: resize control frames (bare or NUL-prefixed JSON — the
	// zoneweaver footer terminal's framing) or raw terminal bytes.
	for {
		_, data, rerr := conn.Read(ctx)
		if rerr != nil {
			return
		}
		if cols, rows, isResize := parseResizeFrame(data); isResize {
			if werr := shell.Resize(cols, rows); werr != nil {
				slog.Debug("ssh terminal resize failed", "session_id", sessionID, "error", werr)
			}
			continue
		}
		if werr := shell.Write(string(data)); werr != nil {
			return
		}
	}
}
