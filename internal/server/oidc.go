package server

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/oidc"
)

const (
	oidcStartWindow   = time.Minute
	oidcStartsPerSlot = 6
	oidcLoginMessage  = "OIDC login successful"
)

type startLimiter struct {
	mu     sync.Mutex
	visits map[string][]time.Time
}

func newStartLimiter() *startLimiter {
	return &startLimiter{visits: map[string][]time.Time{}}
}

func (l *startLimiter) allow(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()
	for visitor, stamps := range l.visits {
		fresh := stamps[:0]
		for _, stamp := range stamps {
			if now.Sub(stamp) < oidcStartWindow {
				fresh = append(fresh, stamp)
			}
		}
		if len(fresh) == 0 {
			delete(l.visits, visitor)
			continue
		}
		l.visits[visitor] = fresh
	}
	if len(l.visits[host]) >= oidcStartsPerSlot {
		return false
	}
	l.visits[host] = append(l.visits[host], now)
	return true
}

type deviceStartResponse struct {
	// Opaque agent-side flow id for GET /api/auth/oidc/device-status (the device_code never leaves the agent)
	Handle string `json:"handle"`
	// Short code the user types (or confirms) at the identity provider
	UserCode string `json:"user_code"`
	// Where the user approves the login
	VerificationURI string `json:"verification_uri"`
	// verification_uri with the user_code embedded (link/QR target)
	VerificationURIComplete string `json:"verification_uri_complete"`
	// Seconds until this login attempt expires
	ExpiresIn int `json:"expires_in"`
	// Suggested seconds between device-status polls
	Interval int `json:"interval"`
}

type deviceStatusResponse struct {
	// pending | approved | denied | expired | failed
	Status string `json:"status"`
	// approved only: the minted key's entity id
	EntityID int64 `json:"entity_id,omitempty"`
	// approved only: the minted key's name (the account's email, or its subject)
	Name string `json:"name,omitempty"`
	// approved only: always admin
	Role string `json:"role,omitempty"`
	// approved only
	Message string `json:"message,omitempty"`
}

type silentStartResponse struct {
	// The IdP authorize URL (response_type=code, loopback redirect_uri, S256 PKCE challenge, prompt=none) — navigate the browser here; the agent holds the state and verifier
	AuthorizeURL string `json:"authorize_url"`
}

type codeStartResponse struct {
	Handle       string `json:"handle"`
	AuthorizeURL string `json:"authorize_url"`
	ManualURL    string `json:"manual_url"`
	ExpiresIn    int    `json:"expires_in"`
}

type codeExchangeRequest struct {
	Handle string `json:"handle"`
	Code   string `json:"code"`
}

type codeExchangeResponse struct {
	Status string `json:"status"`
}

func remoteIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// @Summary		Start a federated device login
// @Description	Public, rate-limited (6 starts per source address per minute). Direct-mode federated login via the OAuth device grant (RFC 8628, the frozen cross-agent wire — a Go-agent-only surface; auth[] advertises oidc only when oidc.enabled): the agent calls the issuer's discovered device_authorization endpoint and answers the user code + verification URI the UI shows. The device_code NEVER leaves the agent — handle is an opaque agent-side flow id, and the agent itself polls the identity provider (honoring the grant's interval/slow_down) while the UI polls GET /api/auth/oidc/device-status freely. On approval the agent validates the tokens against the issuer's JWKS, holds them in memory (background-refreshed), and mints a local admin API key. The FIRST successful login BINDS the agent to that account (TOFU, the bootstrap-key model; persisted in oidc.json beside the config); later logins by other accounts are refused unless listed in oidc.allowed_users.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	deviceStartResponse	"Device login started"
// @Failure		429	{object}	problem.Body	"Too many login attempts from this address"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable or without a usable device grant"
// @Failure		503	{object}	problem.Body	"OIDC login is disabled"
// @Router			/api/auth/oidc/device-start [post]
func (s *Server) handleOIDCDeviceStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	if !s.oidcStarts.allow(r.RemoteAddr) {
		taskError(w, http.StatusTooManyRequests, "Too many login attempts — try again in a minute")
		return
	}
	handle, authorization, err := s.oidcMgr.Start(r.Context())
	if err != nil {
		slog.Warn("oidc device start failed", "error", err)
		taskError(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
		return
	}
	writeJSON(w, deviceStartResponse{
		Handle:                  handle,
		UserCode:                authorization.UserCode,
		VerificationURI:         authorization.VerificationURI,
		VerificationURIComplete: authorization.VerificationURIComplete,
		ExpiresIn:               authorization.ExpiresIn,
		Interval:                authorization.Interval,
	})
}

// @Summary		Poll a federated device login
// @Description	Public. While the flow is pending the request stays open until the status changes or the grant's own interval elapses, then answers; wait=0 answers at once. So a client asks again as soon as an answer arrives and never on a timer. Answers {status} while the flow runs: pending; denied = the ACCOUNT was refused (the human clicked Deny at the identity provider, or the account is not the bound one and not in oidc.allowed_users); expired; failed = the agent could not complete the exchange or validation (identity-provider outage, token rejected — the agent log names the cause; trying again is reasonable). On approval, EXACTLY ONCE, {status: "approved", entity_id, name, role, message} with the browser session cookie __Host-hwa_session (HttpOnly) set on the answer for the minted local admin key; the key itself never reaches the page. After that one delivery (and after the first expired answer) the handle is forgotten and further polls answer 404. Identity comes from the id_token when the provider mints one, else the ACCESS token's claims (Spring Authorization Server's device grant issues no id_token) — validated against the issuer's JWKS either way, account id = UUID claim with sub fallback.
// @Tags			Local Login
// @Produce		json
// @Param			handle	query	string	true	"The device-start answer's opaque flow id"
// @Param			wait	query	string	false	"0 answers the current status at once instead of holding the request open"
// @Success		200	{object}	deviceStatusResponse	"Flow status (credential fields present only on the single approved answer)"
// @Failure		404	{object}	problem.Body	"Unknown, already-delivered, or expired-and-forgotten handle"
// @Failure		503	{object}	problem.Body	"OIDC login is disabled"
// @Router			/api/auth/oidc/device-status [get]
func (s *Server) handleOIDCDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	handle := r.URL.Query().Get("handle")
	if r.URL.Query().Get("wait") != "0" {
		s.oidcMgr.Await(r.Context(), handle)
	}
	status, credential, ok := s.oidcMgr.Status(handle)
	if !ok {
		taskError(w, http.StatusNotFound, "Unknown login handle")
		return
	}
	response := deviceStatusResponse{Status: status}
	if credential != nil {
		if !s.openSession(w, credential.EntityID) {
			return
		}
		response.EntityID = credential.EntityID
		response.Name = credential.Name
		response.Role = credential.Role
		response.Message = oidcLoginMessage
	}
	writeJSON(w, response)
}

// @Summary		Start a silent SSO pre-check
// @Description	Public, rate-limited (shared with device-start: 6 per source address per minute). The identity-first login probe (a Go-agent-only surface): mints state + a PKCE S256 verifier held agent-side and answers the IdP authorize URL with prompt=none — the UI navigates there; a live IdP session comes straight back to GET /api/auth/oidc/callback with a code and signs in without any interaction, no session bounces back benignly. NEVER auto-fires anything — this endpoint only returns a URL. Fast-fails when the identity provider is unreachable (cached discovery; a cold probe is bounded to ~3s) so an offline machine loses milliseconds, never hangs.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	silentStartResponse	"Authorize URL minted"
// @Failure		429	{object}	problem.Body	"Too many attempts from this address"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable or without an authorization endpoint"
// @Failure		503	{object}	problem.Body	"OIDC login is disabled"
// @Router			/api/auth/oidc/silent-start [post]
func (s *Server) handleOIDCSilentStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	if !s.oidcStarts.allow(r.RemoteAddr) {
		taskError(w, http.StatusTooManyRequests, "Too many login attempts — try again in a minute")
		return
	}
	authorizeURL, err := s.oidcMgr.StartSilent(r.Context())
	if err != nil {
		slog.Warn("oidc silent start failed", "error", err)
		taskError(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
		return
	}
	writeJSON(w, silentStartResponse{AuthorizeURL: authorizeURL})
}

// @Summary		Start a federated code login
// @Description	Public, rate-limited (shared with device-start: 6 per source address per minute). The RFC 8252 authorization-code login beside the device grant (features advertises it as oidc-code while oidc.enabled): mints state, a PKCE S256 verifier and an agent-side handle, and answers two interactive authorize URLs (no prompt=none) carrying that one state and PKCE challenge. manual_url names the issuer's /oauth2/code page as redirect_uri on every call, where the person copies the shown code (code#state) and pastes it into POST /api/auth/oidc/code; the UI draws it as the copyable fallback. authorize_url, the one the UI opens in a new tab, names this agent's GET /api/auth/oidc/callback as redirect_uri for a loopback peer, so the browser lands back here and the login completes by itself, and equals manual_url for any other peer. Either way the UI learns the outcome through the held GET /api/auth/oidc/device-status with the handle, exactly as for the device grant; expires_in is the flow's life in seconds and the agent never polls the issuer for it.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	codeStartResponse	"Code login started"
// @Failure		429	{object}	problem.Body	"Too many login attempts from this address"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable or without an authorization endpoint"
// @Failure		503	{object}	problem.Body	"OIDC login is disabled"
// @Router			/api/auth/oidc/code-start [post]
func (s *Server) handleOIDCCodeStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	if !s.oidcStarts.allow(r.RemoteAddr) {
		taskError(w, http.StatusTooManyRequests, "Too many login attempts — try again in a minute")
		return
	}
	handle, authorizeURL, manualURL, expiresIn, err := s.oidcMgr.StartCode(r.Context(), remoteIsLoopback(r.RemoteAddr))
	if err != nil {
		slog.Warn("oidc code start failed", "error", err)
		taskError(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
		return
	}
	writeJSON(w, codeStartResponse{Handle: handle, AuthorizeURL: authorizeURL, ManualURL: manualURL, ExpiresIn: expiresIn})
}

// @Summary		Redeem a pasted federated login code
// @Description	Public, rate-limited (shared with device-start). The other-machine half of the code login: the body carries the code-start handle and the code the person copied from the issuer's /oauth2/code page, code#state when that page showed one. The flow must still be pending, and a state that rides along must be the flow's own. The agent exchanges the code with the flow's verifier, validates the token (issuer JWKS, UUID-first identity, TOFU binding), mints the OIDC admin key and settles the handle, then answers {status} alone — approved, denied (the account is not the bound one and not in oidc.allowed_users) or failed; the credential itself is delivered exactly once by the held GET /api/auth/oidc/device-status.
// @Tags			Local Login
// @Accept			json
// @Produce		json
// @Param			request	body		codeExchangeRequest		true	"The handle and the pasted code"
// @Success		200		{object}	codeExchangeResponse	"The settled status"
// @Failure		400		{object}	problem.Body			"Unreadable body, missing handle or code, or a state that is not the flow's"
// @Failure		404		{object}	problem.Body			"Unknown login handle"
// @Failure		409		{object}	problem.Body			"The login is no longer pending"
// @Failure		429		{object}	problem.Body			"Too many attempts from this address"
// @Failure		503		{object}	problem.Body			"OIDC login is disabled"
// @Router			/api/auth/oidc/code [post]
func (s *Server) handleOIDCCode(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	if !s.oidcStarts.allow(r.RemoteAddr) {
		taskError(w, http.StatusTooManyRequests, "Too many login attempts — try again in a minute")
		return
	}
	var body codeExchangeRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	code, state, _ := strings.Cut(strings.TrimSpace(body.Code), "#")
	if body.Handle == "" || code == "" {
		taskError(w, http.StatusBadRequest, "Login handle and code required")
		return
	}
	status, err := s.oidcMgr.SubmitCode(r.Context(), body.Handle, code, state)
	switch {
	case errors.Is(err, oidc.ErrUnknownHandle):
		taskError(w, http.StatusNotFound, "Unknown login handle")
		return
	case errors.Is(err, oidc.ErrFlowNotPending):
		taskError(w, http.StatusConflict, "The login is no longer pending")
		return
	case errors.Is(err, oidc.ErrStateMismatch):
		taskError(w, http.StatusBadRequest, "The pasted state does not belong to this login")
		return
	}
	writeJSON(w, codeExchangeResponse{Status: status})
}

// @Summary		SSO callback
// @Description	Browser redirect target of both authorize round-trips (registered at the IdP as the loopback redirect_uri) — never called by API clients. When iss rides along (RFC 9207) it must name the configured issuer. A state minted at silent-start takes the silent path: benign IdP answers (login_required, interaction_required, consent_required, access_denied) and EVERY hard failure (unknown/expired state, exchange or validation error, non-bound account) all 302 to /login?sso=unavailable — silent must never strand the browser on an error page. A state minted at code-start on a loopback peer takes the interactive path: error=access_denied settles the handle denied and any other error, iss mismatch or exchange failure settles it failed, each answered with a problem body on this tab while the UI's held GET /api/auth/oidc/device-status learns the status. On success, either path exchanges the code with the held PKCE verifier, validates the token (issuer JWKS, UUID-first identity, TOFU binding), mints the OIDC admin key, and 302s the browser to the /#tray= claim path carrying a single-use grant that answers THAT key — the tray-claim exchange the UI already speaks, now with a federated identity.
// @Tags			Local Login
// @Param			state	query	string	false	"The flow id minted at silent-start or code-start"
// @Param			code	query	string	false	"The IdP's authorization code"
// @Param			iss		query	string	false	"The IdP's issuer identifier (RFC 9207), refused when it is not the configured one"
// @Param			error	query	string	false	"The IdP's OAuth error (login_required and friends bounce benignly on the silent path)"
// @Success		302	"To /#tray=<one-time grant> on success; to /login?sso=unavailable on a silent-path failure"
// @Failure		400	{object}	problem.Body	"Code path: iss mismatch or no code"
// @Failure		403	{object}	problem.Body	"Code path: the person denied the login at the IdP"
// @Failure		502	{object}	problem.Body	"Code path: the IdP refused the login or the exchange failed"
// @Router			/api/auth/oidc/callback [get]
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	unavailable := func() {
		http.Redirect(w, r, "/login?sso=unavailable", http.StatusFound)
	}
	if !s.cfg.OIDC.Enabled {
		unavailable()
		return
	}
	query := r.URL.Query()
	iss := query.Get("iss")
	issMismatch := iss != "" && strings.TrimRight(iss, "/") != strings.TrimRight(s.oidcMgr.Issuer(), "/")
	if _, isCode := s.oidcMgr.CodeFlowHandle(query.Get("state")); isCode {
		s.codeCallback(w, r, query.Get("state"), query.Get("code"), query.Get("error"), issMismatch)
		return
	}
	if issMismatch {
		slog.Warn("oidc callback iss does not name the configured issuer", "iss", iss)
		unavailable()
		return
	}
	if oauthError := query.Get("error"); oauthError != "" {
		slog.Info("oidc silent probe answered without a session", "error", oauthError)
		unavailable()
		return
	}
	state, code := query.Get("state"), query.Get("code")
	if state == "" || code == "" {
		unavailable()
		return
	}
	credential, err := s.oidcMgr.ExchangeSilent(r.Context(), state, code)
	if err != nil {
		slog.Warn("oidc silent callback failed", "error", err)
		unavailable()
		return
	}
	grant, err := s.trayTokens.MintForKey(credential.EntityID)
	if err != nil {
		slog.Error("oidc silent handoff mint failed", "error", err)
		unavailable()
		return
	}
	slog.Info("oidc silent login succeeded", "entity_id", credential.EntityID, "name", credential.Name)
	http.Redirect(w, r, "/#tray="+grant, http.StatusFound)
}

func (s *Server) codeCallback(w http.ResponseWriter, r *http.Request, state, code, oauthError string, issMismatch bool) {
	switch {
	case issMismatch:
		s.oidcMgr.RefuseCode(state, oidc.StatusFailed)
		taskError(w, http.StatusBadRequest, "The callback's iss does not name the configured issuer")
		return
	case oauthError == "access_denied":
		s.oidcMgr.RefuseCode(state, oidc.StatusDenied)
		taskError(w, http.StatusForbidden, "Login denied at the identity provider")
		return
	case oauthError != "":
		s.oidcMgr.RefuseCode(state, oidc.StatusFailed)
		taskError(w, http.StatusBadGateway, "Identity provider refused the login: "+oauthError)
		return
	case code == "":
		s.oidcMgr.RefuseCode(state, oidc.StatusFailed)
		taskError(w, http.StatusBadRequest, "Authorization code required")
		return
	}
	credential, err := s.oidcMgr.ExchangeCode(r.Context(), state, code)
	if err != nil {
		slog.Warn("oidc code callback failed", "error", err)
		taskError(w, http.StatusBadGateway, "Login failed: "+err.Error())
		return
	}
	grant, err := s.trayTokens.MintForKey(credential.EntityID)
	if err != nil {
		slog.Error("oidc code handoff mint failed", "error", err)
		taskError(w, http.StatusInternalServerError, "Login handoff failed")
		return
	}
	http.Redirect(w, r, "/#tray="+grant, http.StatusFound)
}
