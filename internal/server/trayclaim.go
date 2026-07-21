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

type trayClaimResponse struct {
	APIKey  string `json:"api_key"`
	Message string `json:"message"`
}

// handleTrayClaim exchanges a tray one-time token for a fresh admin API key.
// Public route: the token itself is the credential — minted seconds earlier
// by the local user's physical tray click, single-use, 60s TTL. This is what
// lets a desktop user open a signed-in UI without ever seeing a login or the
// setup token (which remains the headless/remote path).
//
//	@Summary		Exchange a tray one-time token for an admin API key
//	@Description	Public: the token itself is the credential — minted seconds earlier by the local user's physical tray Open click (or an hwa:// protocol invocation, or the silent-SSO callback's handoff), carried in the URL fragment, single-use, 60-second TTL. This is how a desktop user gets a signed-in UI without ever seeing a login screen. A silent-SSO grant answers the OIDC-minted admin key (named for the federated account); plain tray grants mint a fresh key named after the local OS account. Each tray-key mint also REAPS older tray-handoff keys beyond the newest 5 (every Open mints a key and nothing else retires them; unbounded piles make the cold-boot bcrypt scan crawl) — a browser tab holding a reaped key re-signs-in via the tray.
//	@Tags			Local Login
//	@Accept			json
//	@Produce		json
//	@Param			request	body		trayClaimRequest	true	"Tray claim request"
//	@Success		200		{object}	trayClaimResponse	"The admin key (SSO-minted when the grant carries one, else fresh and named after the local OS account)"
//	@Failure		400		{object}	auth.ErrorMsg		"Missing token"
//	@Failure		403		{object}	auth.ErrorMsg		"Unknown, expired, or already-used token"
//	@Router			/auth/tray-claim [post]
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
	if boundKey != "" {
		slog.Info("silent-sso handoff key claimed")
		writeJSON(w, trayClaimResponse{
			APIKey:  boundKey,
			Message: "Login successful",
		})
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

	writeJSON(w, trayClaimResponse{
		APIKey:  apiKey,
		Message: "Tray login successful",
	})
}

type protocolOpenRequest struct {
	// Contents of the running agent's protocol.secret file
	Secret string `json:"secret" binding:"required"`
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
//	@Description	Public but secret-gated: when the OS spawns a fresh agent process for an hwa://open invocation (Windows registry handler, Linux .desktop handler), that process forwards the action here and exits. The per-boot secret file (0600, beside the running agent's config) authenticates it — web pages cannot read local files, so possession proves a local same-user process. On success the running agent opens the signed-in UI in the user's browser, exactly like a tray Open click.
//	@Tags			Local Login
//	@Accept			json
//	@Produce		json
//	@Param			request	body		protocolOpenRequest	true	"Protocol open request"
//	@Success		200		{object}	protocolOpenResponse	"Action accepted; the agent is opening the browser"
//	@Failure		400		{object}	auth.ErrorMsg		"Missing secret"
//	@Failure		403		{object}	auth.ErrorMsg		"Invalid secret"
//	@Router			/protocol/open [post]
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
	slog.Info("protocol handoff accepted; opening the signed-in UI")
	// The response must not wait on the browser launch.
	go s.openUI()

	writeJSON(w, protocolOpenResponse{
		Message: "Opening the Hyperweaver UI",
	})
}
