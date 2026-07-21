package server

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	oidcStartWindow   = time.Minute
	oidcStartsPerSlot = 6
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
	// Opaque agent-side flow id for GET /auth/oidc/device-status (the device_code never leaves the agent)
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
	// pending | approved | denied | expired
	Status string `json:"status"`
	// approved only, delivered exactly once: the minted local admin API key
	APIKey string `json:"api_key,omitempty"`
	// approved only: the minted key's entity id
	EntityID int64 `json:"entity_id,omitempty"`
	// approved only: the minted key's name (the account's email, or its subject)
	Name string `json:"name,omitempty"`
	// approved only: always admin
	Role string `json:"role,omitempty"`
	// approved only
	Message string `json:"message,omitempty"`
}

// @Summary		Start a federated device login
// @Description	Public, rate-limited (6 starts per source address per minute). Direct-mode federated login via the OAuth device grant (RFC 8628, the frozen cross-agent wire — a Go-agent-only surface; auth[] advertises oidc only when oidc.enabled): the agent calls the issuer's discovered device_authorization endpoint and answers the user code + verification URI the UI shows. The device_code NEVER leaves the agent — handle is an opaque agent-side flow id, and the agent itself polls the identity provider (honoring the grant's interval/slow_down) while the UI polls GET /auth/oidc/device-status freely. On approval the agent validates the tokens against the issuer's JWKS, holds them in memory (background-refreshed), and mints a local admin API key. The FIRST successful login BINDS the agent to that account (TOFU, the bootstrap-key model; persisted in oidc.json beside the config); later logins by other accounts are refused unless listed in oidc.allowed_users.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	deviceStartResponse	"Device login started"
// @Failure		429	{object}	taskErrorBody	"Too many login attempts from this address"
// @Failure		502	{object}	taskErrorBody	"Identity provider unreachable or without a usable device grant"
// @Failure		503	{object}	taskErrorBody	"OIDC login is disabled"
// @Router			/auth/oidc/device-start [post]
func (s *Server) handleOIDCDeviceStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	if !s.oidcStarts.allow(r.RemoteAddr) {
		taskError(w, http.StatusTooManyRequests, "Too many login attempts — try again in a minute")
		return
	}
	answer, err := s.oidcMgr.start(r.Context())
	if err != nil {
		slog.Warn("oidc device start failed", "error", err)
		taskError(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
		return
	}
	writeJSON(w, answer)
}

// @Summary		Poll a federated device login
// @Description	Public. Answers {status} (pending | denied | expired) while the flow runs; on approval, EXACTLY ONCE, the full credential body {status: "approved", api_key, entity_id, name, role, message} — the minted local admin API key the UI stores in its normal auth slot. After that one delivery (and after the first expired answer) the handle is forgotten and further polls answer 404. Poll freely — the agent itself talks to the identity provider at the grant's own pace.
// @Tags			Local Login
// @Produce		json
// @Param			handle	query	string	true	"The device-start answer's opaque flow id"
// @Success		200	{object}	deviceStatusResponse	"Flow status (credential fields present only on the single approved answer)"
// @Failure		404	{object}	taskErrorBody	"Unknown, already-delivered, or expired-and-forgotten handle"
// @Failure		503	{object}	taskErrorBody	"OIDC login is disabled"
// @Router			/auth/oidc/device-status [get]
func (s *Server) handleOIDCDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	status, credential, ok := s.oidcMgr.status(r.URL.Query().Get("handle"))
	if !ok {
		taskError(w, http.StatusNotFound, "Unknown login handle")
		return
	}
	response := deviceStatusResponse{Status: status}
	if credential != nil {
		response.APIKey = credential.apiKey
		response.EntityID = credential.entityID
		response.Name = credential.name
		response.Role = credential.role
		response.Message = credential.message
	}
	writeJSON(w, response)
}
