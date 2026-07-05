package server

import (
	"log/slog"
	"net/http"
	"os/user"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
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

	description := "Created by the tray Open handoff " + time.Now().Format(time.RFC3339)
	entity, err := s.keys.Create(apiKey, trayKeyName(), description, "admin", akCfg.HashRounds)
	if err != nil {
		slog.Error("tray key creation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "Tray login failed")
		return
	}
	slog.Info("tray login key created", "entity_id", entity.ID)

	writeJSON(w, map[string]any{
		"api_key": apiKey,
		"message": "Tray login successful",
	})
}
