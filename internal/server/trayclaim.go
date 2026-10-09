package server

import (
	"log/slog"
	"net/http"
	"os/user"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/protocol"
)

// trayKeyName names tray-minted keys after the local OS account so the UI
// greets the person, not the mechanism. Windows usernames arrive as
// DOMAIN\name — keep the name part. Fallback when the lookup fails.
func trayKeyName() string {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return "Tray-Login"
	}
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}

const (
	trayKeyDescriptionPrefix = "Created by the tray Open handoff "
	// trayKeysKept bounds the tray-minted pile: each Open reaps older
	// handoff keys beyond the newest N (bcrypt-scan latency grows per key).
	trayKeysKept = 5
)

type trayClaimRequest struct {
	// Single-use tray token from the #tray= URL fragment
	Token string `json:"token" binding:"required"`
}

func (s *Server) keyAlive(id int64) bool {
	k, err := s.keys.Get(id)
	return err == nil && k.IsActive
}

func (s *Server) openSession(w http.ResponseWriter, keyID int64) bool {
	handle, err := s.sessions.Create(keyID, s.keyAlive)
	if err != nil {
		slog.Error("session creation failed", "error", err, "entity_id", keyID)
		auth.WriteMsg(w, http.StatusInternalServerError, "The session could not be opened")
		return false
	}
	auth.SetSessionCookie(w, handle)
	return true
}

// handleTrayClaim exchanges a tray one-time token for a browser session on a
// fresh admin key. Public route: the token itself is the credential — minted
// seconds earlier by the local user's physical tray click, single-use, 60s
// TTL. This is what lets a desktop user open a signed-in UI without ever
// seeing a login or the setup token (which remains the headless/remote path).
//
//	@Summary		Exchange a tray one-time token for a browser session
//	@Description	Public: the token itself is the credential — minted seconds earlier by the local user's physical tray Open click (or a protocol invocation, or the SSO callback's handoff), carried in the URL fragment, single-use, 60-second TTL. The answer is 204 with the browser session cookie set, __Host-hwa_session (HttpOnly; Secure; SameSite=Strict; Path=/, an opaque handle mapped to the key); the key itself never reaches the page. An SSO grant opens the session on the OIDC-minted admin key (named for the federated account); a plain tray grant mints a fresh admin key named after the local OS account. Each tray-key mint also REAPS older tray-handoff keys beyond the newest 5, and a session on a reaped key answers 401 and signs in again through the tray.
//	@Tags			Local Login
//	@Accept			json
//	@Param			request	body		trayClaimRequest	true	"Tray claim request"
//	@Success		204		"Session opened, cookie set"
//	@Failure		400		{object}	problem.Body		"Missing token"
//	@Failure		403		{object}	problem.Body		"Unknown, expired, or already-used token"
//	@Router			/api/auth/tray-claim [post]
func (s *Server) handleTrayClaim(w http.ResponseWriter, r *http.Request) {
	var body trayClaimRequest
	if err := decodeBody(r, &body); err != nil || body.Token == "" {
		auth.WriteMsg(w, http.StatusBadRequest, "Tray token required")
		return
	}

	boundKey, ok := s.trayTokens.Claim(body.Token)
	if !ok {
		auth.WriteMsg(w, http.StatusForbidden, "Invalid or expired tray token")
		return
	}
	if boundKey != 0 {
		slog.Info("sso handoff key claimed", "entity_id", boundKey)
		if s.openSession(w, boundKey) {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}

	akCfg := s.cfg.APIKeys
	apiKey, err := keys.GenerateKeyString(akCfg.KeyLength)
	if err != nil {
		slog.Error("tray key generation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "Tray login failed")
		return
	}

	description := trayKeyDescriptionPrefix + time.Now().Format(time.RFC3339)
	entity, err := s.keys.Create(apiKey, trayKeyName(), description, "admin", akCfg.HashRounds)
	if err != nil {
		slog.Error("tray key creation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "Tray login failed")
		return
	}
	slog.Info("tray login key created", "entity_id", entity.ID)
	if removed, perr := s.keys.PruneByDescriptionPrefix(trayKeyDescriptionPrefix, trayKeysKept); perr != nil {
		slog.Warn("tray key prune failed", "error", perr)
	} else if removed > 0 {
		slog.Info("stale tray keys pruned", "removed", removed)
	}
	if s.openSession(w, entity.ID) {
		w.WriteHeader(http.StatusNoContent)
	}
}

type sessionRequest struct {
	// The API key a person pastes
	APIKey string `json:"api_key"`
}

// @Summary		Open a browser session for a pasted API key
// @Description	Public: the body's key is verified like any credential and the answer is 204 with the browser session cookie set, __Host-hwa_session (HttpOnly; Secure; SameSite=Strict; Path=/); 401 for a key the agent does not know or that is revoked. The page keeps no key and sends no token: every later request rides the cookie, and every method but GET, HEAD and OPTIONS must arrive same-origin, judged by the browser's Sec-Fetch-Site header with Origin against Host as the fallback, else 403.
// @Tags			Local Login
// @Accept			json
// @Param			request	body	sessionRequest	true	"The pasted key"
// @Success		204	"Session opened, cookie set"
// @Failure		400	{object}	problem.Body	"Missing key"
// @Failure		401	{object}	problem.Body	"Unknown or revoked key"
// @Router			/api/auth/session [post]
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var body sessionRequest
	if err := decodeBody(r, &body); err != nil || body.APIKey == "" {
		auth.WriteMsg(w, http.StatusBadRequest, "API key required")
		return
	}
	match, err := s.keys.Verify(body.APIKey)
	if err != nil {
		slog.Error("session key validation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "API key validation failed")
		return
	}
	if match == nil {
		auth.Unauthorized(w, "", "", "Unknown or revoked API key")
		return
	}
	if s.openSession(w, match.ID) {
		w.WriteHeader(http.StatusNoContent)
	}
}

// @Summary		End the browser session
// @Description	Minimum role: viewer. Forgets the session the __Host-hwa_session cookie names and clears the cookie with Max-Age=0; the key behind it stays. Sent with the cookie, it must arrive same-origin like every write.
// @Tags			Local Login
// @Success		204	"Session ended, cookie cleared"
// @Failure		401	{object}	problem.Body	"No live session or credential"
// @Failure		403	{object}	problem.Body	"Cross-origin request"
// @Router			/api/auth/logout [post]
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if session, err := r.Cookie(auth.SessionCookie); err == nil && session.Value != "" {
		if eerr := s.sessions.End(session.Value); eerr != nil {
			slog.Error("session end failed", "error", eerr)
		}
	}
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

type protocolOpenRequest struct {
	// Contents of the running agent's protocol.secret file
	Secret string `json:"secret" binding:"required"`
	// The link's raw query, the deploy vocabulary alone (create=machine with the box members, or the provisioner members with provisioner_catalog); the UI lands on /?query
	Query string `json:"query,omitempty"`
}

type protocolOpenResponse struct {
	Message string `json:"message"`
}

// handleProtocolOpen serves the hwa:// single-instance handoff (Windows and
// Linux): the OS spawns a fresh agent process for a protocol invocation, and
// that process forwards the action here before exiting. The per-boot secret
// file (0600, beside the config) authenticates it — a web page cannot read
// local files, so possession proves a local same-user process, the same
// trust a tray click carries. The signed-in token only ever appears in the
// fresh browser tab this agent opens, never in this response.
//
//	@Summary		hwa:// single-instance handoff
//	@Description	Public but secret-gated: when the OS spawns a fresh agent process for a protocol invocation, <scheme>://open?<query> or the RFC 8252 section 7.1 form <scheme>:/open?<query> under hwa, hyperweaver-agent or com.startcloud.hyperweaver-agent (Windows registry handler, Linux .desktop handler), that process forwards the action here and exits. The per-boot secret file (0600, beside the running agent's config) authenticates it — web pages cannot read local files, so possession proves a local same-user process. On success the running agent opens the signed-in UI in the user's browser, exactly like a tray Open click; a query carried by the link (the deploy vocabulary of at most 2048 bytes: create=machine with box, box_version, box_arch, box_url or provisioner, provisioner_version, provisioner_url, provisioner_catalog, the URL of the catalog document the family came from, and the box_<provider> family, box_virtualbox, box_utm and the like, the box the version is verified with on that provider as organization/name@version@architecture@url) lands on /?query so the hosts page opens the create wizard seeded, any other key refused 400.
//	@Tags			Local Login
//	@Accept			json
//	@Produce		json
//	@Param			request	body		protocolOpenRequest	true	"Protocol open request"
//	@Success		200		{object}	protocolOpenResponse	"Action accepted; the agent is opening the browser"
//	@Failure		400		{object}	problem.Body		"Missing secret, or a query outside the deploy vocabulary"
//	@Failure		403		{object}	problem.Body		"Invalid secret"
//	@Router			/api/protocol/open [post]
func (s *Server) handleProtocolOpen(w http.ResponseWriter, r *http.Request) {
	var body protocolOpenRequest
	if err := decodeBody(r, &body); err != nil || body.Secret == "" {
		auth.WriteMsg(w, http.StatusBadRequest, "Protocol secret required")
		return
	}
	if !protocol.VerifySecret(s.cfg.ProtocolSecretPath(), body.Secret) {
		slog.Warn("protocol handoff with invalid secret", "remote", r.RemoteAddr)
		auth.WriteMsg(w, http.StatusForbidden, "Invalid protocol secret")
		return
	}
	if err := protocol.ValidateQuery(body.Query); err != nil {
		auth.WriteMsg(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("protocol handoff accepted; opening the signed-in UI")
	// The response must not wait on the browser launch.
	go s.openUI(body.Query)

	writeJSON(w, protocolOpenResponse{
		Message: "Opening the Hyperweaver UI",
	})
}

type protocolHandoffResponse struct {
	Message string `json:"message"`
}

// @Summary		Restart handoff
// @Description	Public but secret-gated, the restart's successor side: the freshly spawned agent posts the running agent's protocol secret before it opens any database or binds any port. With a restart pending the running agent holds this request open while it closes its listeners, stops its services and closes its databases, then answers 200 and exits; the answer, or the connection closing with it, is the successor's signal that the port and the database files are free. Without a pending restart (an ordinary second launch) it answers 409 and the caller proceeds as a normal launch.
// @Tags			Local Login
// @Accept			json
// @Produce		json
// @Param			request	body		protocolOpenRequest		true	"The running agent's protocol secret"
// @Success		200		{object}	protocolHandoffResponse	"Port and databases released"
// @Failure		400		{object}	problem.Body			"Missing secret"
// @Failure		403		{object}	problem.Body			"Invalid secret"
// @Failure		409		{object}	problem.Body			"No restart is pending"
// @Router			/api/protocol/handoff [post]
func (s *Server) handleProtocolHandoff(w http.ResponseWriter, r *http.Request) {
	var body protocolOpenRequest
	if err := decodeBody(r, &body); err != nil || body.Secret == "" {
		auth.WriteMsg(w, http.StatusBadRequest, "Protocol secret required")
		return
	}
	if !protocol.VerifySecret(s.cfg.ProtocolSecretPath(), body.Secret) {
		slog.Warn("restart handoff with invalid secret", "remote", r.RemoteAddr)
		auth.WriteMsg(w, http.StatusForbidden, "Invalid protocol secret")
		return
	}
	if !s.successorPending() {
		auth.WriteMsg(w, http.StatusConflict, "No restart is pending")
		return
	}
	slog.Info("restart successor is waiting for the release")
	select {
	case <-s.released:
	case <-r.Context().Done():
		return
	}
	writeJSON(w, protocolHandoffResponse{Message: "Released"})
}
