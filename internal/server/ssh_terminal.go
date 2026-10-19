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

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
)

// SSH terminal sessions — the base's SSHTerminal family on this agent's
// transport: POST /api/machines/{name}/ssh/start mints a session, the WebSocket
// at /api/ssh/{sessionId}?ticket=... opens the interactive shell on its first
// connect and re-attaches to it afterwards. The shell prefers the provisioning
// NAT ssh port-forward (the pipeline's transport, immune to guest network
// reconfiguration) and falls back to the document's control IP —
// resolveTransport's exact ladder. Sessions are in-memory: shells never
// survive an agent restart (the base marks them all closed at startup for the
// same reason).

// sshSession is one terminal session (the base's SSHSession row shape).
type sshSession struct {
	ID           string    `json:"id"`
	MachineName  string    `json:"machine_name"`
	Status       string    `json:"status"` // connecting | active | closed | failed
	SSHHost      string    `json:"ssh_host"`
	SSHPort      int       `json:"ssh_port"`
	SSHUsername  string    `json:"ssh_username"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`

	person      string
	credentials *sshrun.Credentials
	shell       *sshrun.Shell
	link        terminalLink
	done        chan struct{}
	startMu     sync.Mutex
}

// sshStartRequest is POST /api/machines/{name}/ssh/start's optional body: the vault row the shell signs in with.
type sshStartRequest struct {
	CredentialID string `json:"credential_id"`
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

func (s *sshSessions) touch(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session, ok := s.sessions[id]; ok {
		session.LastActivity = time.Now()
	}
}

// idleOf lists the live sessions the key createdBy started that no socket is attached to.
func (s *sshSessions) idleOf(createdBy string) []*sshSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	idle := []*sshSession{}
	for _, session := range s.sessions {
		if session.CreatedBy == createdBy && session.Status != "closed" && !session.link.attached() {
			idle = append(idle, session)
		}
	}
	return idle
}

// close tears a session's shell down and marks it closed; ended is true the first time.
func (s *sshSessions) close(id string) (session *sshSession, ended bool) {
	s.mu.Lock()
	session, ok := s.sessions[id]
	var shell *sshrun.Shell
	if ok && session.Status != "closed" {
		shell = session.shell
		session.shell = nil
		session.Status = "closed"
		session.LastActivity = time.Now()
		close(session.done)
		ended = true
	}
	s.mu.Unlock()
	if shell != nil {
		shell.Close()
	}
	return session, ended
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
// /api/machines/{name}/ssh/start — each call is an independent session).
//
//	@Summary		Start an SSH terminal session
//	@Description	Minimum role: operator. Mints an SSH terminal session for a RUNNING machine, created_by the calling key; the shell opens when the first terminal connects at the /api/ssh/{sessionId} WebSocket and lives until DELETE /api/ssh/sessions/{sessionId}/stop, the remote shell's exit, the calling key's revocation or deletion while no socket is attached, or the agent's stop; a socket's close leaves it running, its last output kept for the next socket. session-started {kind: ssh, id, machine_name} goes to the person on the sessions topic of GET /api/events. Each call is an independent session. CREDENTIAL: the body's credential_id names a password or ssh_key row of the certs store the caller may read; absent, the machine's credentials[] entry with use ssh (default first) applies, else machines.default_credentials.ssh, else the stored settings (settings.vagrant_user/vagrant_user_pass/vagrant_user_private_key_path; the agent's provisioning key is the last-resort fallback). A row's username comes from its extra.username or extra.user, else settings.vagrant_user; its password or private key and passphrase are resolved on the agent, never sent to the browser. Transport = the pipeline's ladder: the provisioning NAT ssh port-forward first (immune to guest network reconfiguration), the document's control IP as fallback.
//	@Tags			Console
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request		body	sshStartRequest	false	"Optional {credential_id}"
//	@Success		200	{object}	sshSession	"Session created"
//	@Failure		400	"Machine not running, no credentials configured, a credential_id naming no readable password or ssh_key row, or no SSH transport"
//	@Failure		404	"Machine not found"
//	@Router			/api/machines/{machineName}/ssh/start [post]
func (s *Server) handleStartSSHSession(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return
	}
	var body sshStartRequest
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	config := machines.ParseConfiguration(machine)
	credentials := machines.ExtractCredentials(config.Section("settings"))
	var vault *sshrun.Credentials
	row, err := s.pickCredential(r.Context(), machine, s.certReader(r), "ssh", body.CredentialID)
	if err != nil {
		taskError(w, http.StatusBadRequest, "credential_id "+err.Error())
		return
	}
	if row != nil {
		resolved, rerr := machines.SSHCredentialOf(row)
		if rerr != nil {
			taskError(w, http.StatusBadRequest, "credential "+row.ID+": "+rerr.Error())
			return
		}
		if resolved.Username == "" {
			resolved.Username = credentials.Username
		}
		if resolved.PrivateKey == "" {
			resolved.SSHKeyPath = credentials.SSHKeyPath
		}
		credentials.Username = resolved.Username
		vault = &resolved
	}
	if credentials.Username == "" {
		taskError(w, http.StatusBadRequest,
			"SSH credentials not configured. Set settings.vagrant_user in the machine configuration or pick a credential.")
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
	identity := auth.FromContext(r.Context())
	session := &sshSession{
		ID:           id,
		MachineName:  machine.Name,
		Status:       "connecting",
		SSHHost:      host,
		SSHPort:      port,
		SSHUsername:  credentials.Username,
		CreatedBy:    identity.Name,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		person:       s.personOf(identity),
		credentials:  vault,
		done:         make(chan struct{}),
	}
	s.sshSessions.put(session)
	slog.Info("ssh terminal session created", "session_id", id,
		"machine", machine.Name, "host", host, "port", port, "created_by", identity.Name)
	s.publishSession(eventSessionStarted, sessionKindSSH, id, machine.Name, session.person)
	writeJSON(w, session)
}

// handleListSSHSessions mirrors GET /api/ssh/sessions.
//
//	@Summary		List SSH terminal sessions
//	@Description	Minimum role: viewer. Every session the agent holds, newest first, each {id, machine_name, status, ssh_host, ssh_port, ssh_username, created_by, created_at, last_activity}, status connecting, active, closed or failed; a person re-attaches to the live ones their own key started. Sessions are in-memory — an agent restart closes them all.
//	@Tags			Console
//	@Produce		json
//	@Success		200	{array}	sshSession	"Sessions"
//	@Router			/api/ssh/sessions [get]
func (s *Server) handleListSSHSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.sshSessions.snapshot())
}

// handleSSHSessionInfo mirrors GET /api/ssh/sessions/{sessionId}.
//
//	@Summary		SSH session information
//	@Description	Minimum role: viewer.
//	@Tags			Console
//	@Produce		json
//	@Param			sessionId	path	string	true	"SSH session id"
//	@Success		200	{object}	sshSession	"The session"
//	@Failure		404	"SSH session not found"
//	@Router			/api/ssh/sessions/{sessionId} [get]
func (s *Server) handleSSHSessionInfo(w http.ResponseWriter, r *http.Request) {
	session := s.sshSessions.get(r.PathValue("sessionId"))
	if session == nil {
		taskError(w, http.StatusNotFound, "SSH session not found")
		return
	}
	writeJSON(w, session)
}

// handleStopSSHSession mirrors DELETE /api/ssh/sessions/{sessionId}/stop.
//
//	@Summary		Stop an SSH session
//	@Description	Minimum role: operator. Closes the shell, marks the session closed and sends session-ended on the sessions topic to the person who started it, so the tab closes in every open browser.
//	@Tags			Console
//	@Produce		json
//	@Param			sessionId	path	string	true	"SSH session id"
//	@Success		200	{object}	successMessageResponse	"Session stopped"
//	@Failure		404	"SSH session not found"
//	@Router			/api/ssh/sessions/{sessionId}/stop [delete]
func (s *Server) handleStopSSHSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("sessionId")
	if s.sshSessions.get(id) == nil {
		taskError(w, http.StatusNotFound, "SSH session not found")
		return
	}
	s.endSSHSession(id)
	writeJSON(w, successMessageResponse{Success: true, Message: "SSH session stopped."})
}

type successMessageResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// terminalControl is the client → shell control frame (the base's resize
// message; anything non-JSON is raw terminal input).
type terminalControl struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// sshShell answers the session's shell, opening it on the first socket with the session's vault credential or the machine's stored credentials; a session already closed answers nil.
func (s *Server) sshShell(ctx context.Context, session *sshSession, sendText func(string)) (*sshrun.Shell, error) {
	session.startMu.Lock()
	defer session.startMu.Unlock()
	s.sshSessions.mu.Lock()
	shell, status := session.shell, session.Status
	s.sshSessions.mu.Unlock()
	if shell != nil || status == "closed" {
		return shell, nil
	}
	machine, err := s.machines.Get(ctx, session.MachineName)
	if err != nil {
		return nil, err
	}
	config := machines.ParseConfiguration(machine)
	stored := machines.ExtractCredentials(config.Section("settings"))
	credentials := sshrun.Credentials{
		Username:   stored.Username,
		Password:   stored.Password,
		SSHKeyPath: stored.SSHKeyPath,
	}
	if session.credentials != nil {
		credentials = *session.credentials
	}
	basePath := ""
	if machine.Home != nil {
		basePath = *machine.Home
	}
	sendText("Connecting to SSH...\r\n")
	connectCtx, connectCancel := context.WithTimeout(ctx, 20*time.Second)
	defer connectCancel()
	shell, err = sshrun.StartShell(connectCtx, session.SSHHost, session.SSHPort, &credentials,
		basePath, s.cfg.ProvisionKeyPath(), 80, 24, session.link.output)
	if err != nil {
		return nil, err
	}
	s.sshSessions.mu.Lock()
	session.shell = shell
	session.Status = "active"
	session.LastActivity = time.Now()
	s.sshSessions.mu.Unlock()
	go s.watchSSHSession(session, shell)
	return shell, nil
}

func (s *Server) watchSSHSession(session *sshSession, shell *sshrun.Shell) {
	_ = shell.Wait()
	session.link.output("\r\nSSH connection closed.\r\n")
	s.endSSHSession(session.ID)
}

// handleSSHSocket serves the WebSocket at /api/ssh/{sessionId}: dial on the
// first connect, attach on every connect, bidirectional piping, resize
// control frames.
//
//	@Summary		SSH terminal (WebSocket)
//	@Description	WEBSOCKET upgrade — authenticate with ?ticket= (GET /api/ws-ticket) minted with ?machine= matching the session's machine (the frozen cross-agent shape: machine streams take ONLY a matching scoped ticket; a mismatch answers the same 401 as an invalid ticket). The first socket opens the interactive shell (xterm-256color PTY) of a session minted at POST /api/machines/{name}/ssh/start; a later socket attaches to the running shell, the last output it wrote, up to 256 KiB, replayed first, and takes any earlier socket's place. Closing the socket leaves the shell running for the next socket. Wire: remote output arrives as raw text frames; send raw text as terminal input; send {"type": "resize", "cols": N, "rows": N} JSON frames to resize the PTY. "Connecting to SSH..." opens the stream; "SSH connection closed." marks remote exit.
//	@Tags			Console
//	@Param			sessionId	path	string	true	"SSH session id"
//	@Param			ticket	query	string	true	"WebSocket upgrade ticket (GET /api/ws-ticket?machine={name} — must be scoped to the session's machine)"
//	@Success		101	"Switching Protocols — the terminal begins"
//	@Failure		401	"Missing, invalid, or wrong-scope ticket"
//	@Failure		404	"SSH session or machine not found, or the session already closed"
//	@Router			/api/ssh/{sessionId} [get]
func (s *Server) handleSSHSocket(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.ticketScope(w, r)
	if !ok {
		return
	}
	sessionID := r.PathValue("sessionId")
	session := s.sshSessions.get(sessionID)
	if session == nil {
		taskError(w, http.StatusNotFound, "SSH session not found")
		return
	}
	if !requireScope(w, scope, session.MachineName) {
		return
	}
	if session.Status == "closed" {
		taskError(w, http.StatusNotFound, "SSH session is closed")
		return
	}
	if _, err := s.machines.Get(r.Context(), session.MachineName); err != nil {
		taskError(w, http.StatusNotFound, "Machine not found")
		return
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
	go func() {
		select {
		case <-session.done:
			cancel()
		case <-ctx.Done():
		}
	}()

	shell, err := s.sshShell(ctx, session, sendText)
	if err != nil {
		slog.Warn("ssh terminal connect failed", "session_id", sessionID, "error", err)
		s.sshSessions.setStatus(sessionID, "failed")
		sendText("SSH connection error: " + err.Error() + "\r\n")
		return
	}
	if shell == nil {
		sendText("SSH session is closed.\r\n")
		return
	}
	handle := session.link.attach(sendText)
	defer session.link.detach(handle)
	s.sshSessions.touch(sessionID)

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
		s.sshSessions.touch(sessionID)
	}
}
