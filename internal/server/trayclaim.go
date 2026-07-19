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
	Token string `json:"token"`
}

// handleTrayClaim exchanges a tray one-time token for a fresh admin API key.
// Public route: the token itself is the credential — minted seconds earlier
// by the local user's physical tray click, single-use, 60s TTL. This is what
// lets a desktop user open a signed-in UI without ever seeing a login or the
// setup token (which remains the headless/remote path).
func (s *Server) handleTrayClaim(w http.ResponseWriter, r *http.Request) {
	var body trayClaimRequest
	if err := decodeBody(r, &body); err != nil || body.Token == "" {
		auth.WriteMsg(w, http.StatusBadRequest, "Tray token required")
		return
	}

	if !s.trayTokens.Claim(body.Token) {
		auth.WriteMsg(w, http.StatusForbidden, "Invalid or expired tray token")
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

	writeJSON(w, map[string]any{
		"api_key": apiKey,
		"message": "Tray login successful",
	})
}

type protocolOpenRequest struct {
	Secret string `json:"secret"`
}

// handleProtocolOpen serves the hwa:// single-instance handoff (Windows and
// Linux): the OS spawns a fresh agent process for a protocol invocation, and
// that process forwards the action here before exiting. The per-boot secret
// file (0600, beside the config) authenticates it — a web page cannot read
// local files, so possession proves a local same-user process, the same
// trust a tray click carries. The signed-in token only ever appears in the
// fresh browser tab this agent opens, never in this response.
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

	writeJSON(w, map[string]any{
		"message": "Opening the Hyperweaver UI",
	})
}
