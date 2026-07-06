package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
)

// Global secrets endpoints (architecture D-C, SHI's SecretsPage categories):
// admin-only via the central role policy (/secrets is an admin-always
// prefix). GET serves the whole document — plain, nothing masked (Mark's
// ruling: it is the user's local machine, and the generated Hosts.yml
// carries these as SECRETS_* vars anyway). PUT replaces the submitted
// categories, the same top-level shallow-merge shape as PUT /settings.

func (s *Server) handleGetSecrets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.secrets.Get())
}

func (s *Server) handleUpdateSecrets(w http.ResponseWriter, r *http.Request) {
	var categories map[string]json.RawMessage
	if err := decodeBody(r, &categories); err != nil || categories == nil {
		errorResponse(w, http.StatusBadRequest, "Failed to update secrets", "Invalid JSON body")
		return
	}

	if err := s.secrets.Replace(categories); err != nil {
		status := http.StatusInternalServerError
		// Category/name rejections are the caller's to fix.
		if strings.Contains(err.Error(), "unknown secrets category") ||
			strings.Contains(err.Error(), "must match") ||
			strings.Contains(err.Error(), "category ") {
			status = http.StatusBadRequest
		}
		slog.Error("secrets update failed", "error", err)
		errorResponse(w, status, "Failed to update secrets", err.Error())
		return
	}
	slog.Info("secrets updated", "by", auth.FromContext(r.Context()).Name)

	writeJSON(w, map[string]any{
		"success": true,
		"message": "Secrets updated successfully",
	})
}
