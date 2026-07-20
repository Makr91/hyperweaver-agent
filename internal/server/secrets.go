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

// @Summary		The global secrets document
// @Description	Minimum role: admin. The whole store, plain — nothing masked (Mark's ruling: the user's local machine; the generated Hosts.yml carries these as SECRETS_* vars anyway).
// @Tags			Secrets
// @Produce		json
// @Success		200	{object}	secrets.Document	"The secrets document"
// @Router			/secrets [get]
func (s *Server) handleGetSecrets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.secrets.Get())
}

// secretsUpdateResponse is PUT /secrets's answer.
type secretsUpdateResponse struct {
	// Always true on success
	Success bool `json:"success"`
	// Human-readable confirmation
	Message string `json:"message"`
}

// @Summary		Update the global secrets
// @Description	Minimum role: admin. Replaces the submitted categories whole (the same top-level shallow-merge shape as PUT /settings); omitted categories are untouched. Rejected whole on an unknown category or an invalid entry name — the store never half-applies. Persisted atomically to secrets.yaml (0600) beside the config.
// @Tags			Secrets
// @Accept			json
// @Produce		json
// @Param			body	body	secrets.Document	true	"Secrets categories to replace"
// @Success		200	{object}	secretsUpdateResponse	"Secrets persisted"
// @Failure		400	{object}	wrappedError	"Unknown category or invalid entry name"
// @Router			/secrets [put]
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

	writeJSON(w, secretsUpdateResponse{
		Success: true,
		Message: "Secrets updated successfully",
	})
}
