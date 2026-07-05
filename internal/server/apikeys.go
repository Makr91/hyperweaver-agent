package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
)

// API-key management endpoints (Agent API v1 local tier). Paths, payloads,
// status codes, and message texts mirror the Node agent's ApiKeys controller —
// the Hyperweaver UI codes against that exact surface.

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write json response", "error", err)
	}
}

// decodeBody unmarshals a JSON request body into dst, treating an empty body
// as an empty object (the bootstrap endpoint accepts bodyless requests).
func decodeBody(r *http.Request, dst any) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

type bootstrapRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	SetupToken  string `json:"setupToken"`
}

func (s *Server) handleBootstrapKey(w http.ResponseWriter, r *http.Request) {
	akCfg := s.cfg.APIKeys

	if !akCfg.BootstrapEnabled {
		auth.WriteMsg(w, http.StatusForbidden, "Bootstrap endpoint is disabled")
		return
	}
	if s.keys.Count() > 0 && akCfg.BootstrapAutoDisable {
		auth.WriteMsg(w, http.StatusForbidden, "Bootstrap endpoint auto-disabled after first use")
		return
	}

	var body bootstrapRequest
	if err := decodeBody(r, &body); err != nil {
		auth.WriteMsg(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	// Proof-of-ownership: the setup (claim) token is written to a 0600 file
	// beside the config at boot and logged at startup, so only someone with
	// host access can create the first key.
	if akCfg.BootstrapRequireClaimToken {
		if !auth.VerifySetupToken(s.cfg.SetupTokenPath(), body.SetupToken) {
			auth.WriteMsg(w, http.StatusForbidden,
				"Invalid or missing setup token. Read it from the agent host (setup.token beside the config file, or the startup log) and send it as setupToken.")
			return
		}
	}

	apiKey, err := keys.GenerateKeyString(akCfg.KeyLength)
	if err != nil {
		slog.Error("bootstrap key generation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "Bootstrap failed")
		return
	}

	name := body.Name
	if name == "" {
		name = "Bootstrap-Key"
	}
	description := body.Description
	if description == "" {
		description = "Initial bootstrap API key"
	}

	// The first key is always the admin key (Agent API v1 role model).
	if _, err := s.keys.Create(apiKey, name, description, "admin", akCfg.HashRounds); err != nil {
		slog.Error("bootstrap key creation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "Bootstrap failed")
		return
	}

	note := "Bootstrap endpoint will be auto-disabled for future requests"
	if !akCfg.BootstrapAutoDisable {
		note = "Bootstrap endpoint remains enabled per configuration"
	}
	slog.Info("bootstrap api key created", "name", name)

	writeJSON(w, map[string]any{
		"api_key": apiKey,
		"message": "Bootstrap API key generated successfully",
		"note":    note,
	})
}

type generateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Role        string `json:"role"`
}

func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var body generateRequest
	if err := decodeBody(r, &body); err != nil {
		auth.WriteMsg(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" {
		auth.WriteMsg(w, http.StatusBadRequest, "Name is required")
		return
	}

	role := body.Role
	if role == "" {
		role = "admin"
	}
	if !keys.RoleValid(role) {
		auth.WriteMsg(w, http.StatusBadRequest, "role must be one of: admin, operator, viewer")
		return
	}

	akCfg := s.cfg.APIKeys
	apiKey, err := keys.GenerateKeyString(akCfg.KeyLength)
	if err != nil {
		slog.Error("key generation failed", "error", err)
		auth.WriteMsg(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	entity, err := s.keys.Create(apiKey, body.Name, body.Description, role, akCfg.HashRounds)
	if err != nil {
		slog.Error("key creation failed", "error", err, "name", body.Name)
		auth.WriteMsg(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}
	slog.Info("api key created", "name", entity.Name, "role", entity.Role,
		"created_by", auth.FromContext(r.Context()).Name)

	writeJSON(w, map[string]any{
		"api_key":     apiKey,
		"entity_id":   entity.ID,
		"name":        entity.Name,
		"description": entity.Description,
		"role":        entity.Role,
		"message":     "API key generated successfully",
	})
}

// entityJSON is the sanitized key representation (never the hash).
type entityJSON struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Role        string    `json:"role"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
}

func (s *Server) handleListKeys(w http.ResponseWriter, _ *http.Request) {
	list := s.keys.List()
	entities := make([]entityJSON, 0, len(list))
	for _, k := range list {
		entities = append(entities, entityJSON{
			ID:          k.ID,
			Name:        k.Name,
			Description: k.Description,
			Role:        k.Role,
			IsActive:    k.IsActive,
			CreatedAt:   k.CreatedAt,
			LastUsed:    k.LastUsed,
		})
	}
	writeJSON(w, map[string]any{
		"entities": entities,
		"total":    len(entities),
	})
}

func (s *Server) handleKeyInfo(w http.ResponseWriter, r *http.Request) {
	identity := auth.FromContext(r.Context())
	if identity == nil {
		auth.WriteMsg(w, http.StatusUnauthorized, "API key required")
		return
	}
	k, err := s.keys.Get(identity.ID)
	if err != nil {
		auth.WriteMsg(w, http.StatusNotFound, "Entity not found")
		return
	}
	// Same attribute set the Node agent selects for /api-keys/info.
	writeJSON(w, map[string]any{
		"id":          k.ID,
		"name":        k.Name,
		"description": k.Description,
		"role":        k.Role,
		"created_at":  k.CreatedAt,
		"last_used":   k.LastUsed,
	})
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		auth.WriteMsg(w, http.StatusNotFound, "API key not found")
		return
	}

	entity, err := s.keys.Delete(id)
	switch {
	case errors.Is(err, keys.ErrNotFound):
		auth.WriteMsg(w, http.StatusNotFound, "API key not found")
		return
	case errors.Is(err, keys.ErrLastAdmin):
		auth.WriteMsg(w, http.StatusConflict,
			"Cannot delete the last active admin API key — create another admin key first")
		return
	case err != nil:
		slog.Error("key deletion failed", "error", err, "entity_id", idStr)
		auth.WriteMsg(w, http.StatusInternalServerError, "Failed to delete API key")
		return
	}
	slog.Info("api key deleted", "name", entity.Name,
		"deleted_by", auth.FromContext(r.Context()).Name)

	writeJSON(w, map[string]any{
		"message":   "API key deleted successfully",
		"entity_id": idStr,
		"name":      entity.Name,
	})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		auth.WriteMsg(w, http.StatusNotFound, "API key not found")
		return
	}

	entity, err := s.keys.Revoke(id)
	switch {
	case errors.Is(err, keys.ErrNotFound):
		auth.WriteMsg(w, http.StatusNotFound, "API key not found")
		return
	case errors.Is(err, keys.ErrLastAdmin):
		auth.WriteMsg(w, http.StatusConflict,
			"Cannot revoke the last active admin API key — create another admin key first")
		return
	case err != nil:
		slog.Error("key revocation failed", "error", err, "entity_id", idStr)
		auth.WriteMsg(w, http.StatusInternalServerError, "Failed to revoke API key")
		return
	}
	slog.Info("api key revoked", "name", entity.Name,
		"revoked_by", auth.FromContext(r.Context()).Name)

	writeJSON(w, map[string]any{
		"message":   "API key revoked successfully",
		"entity_id": idStr,
		"name":      entity.Name,
	})
}
