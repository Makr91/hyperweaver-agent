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
	SetupToken  string `json:"setupToken"` // 64-character claim token from the agent host
}

type bootstrapKeyResponse struct {
	APIKey  string `json:"api_key"`
	Message string `json:"message"`
	Note    string `json:"note"`
}

// @Summary		Create the first API key
// @Description	Public, but gated: requires `api_keys.bootstrap_enabled`, locks after the first key when `bootstrap_auto_disable` is on, and (by default) demands the setup claim token written to `setup.token` beside the agent's config file and printed to the startup log — proof of host ownership. The first key is always an admin key.
// @Tags			API Keys
// @Accept			json
// @Produce		json
// @Param			body	body	bootstrapRequest	false	"Optional name, description, and setup claim token"
// @Success		200	{object}	bootstrapKeyResponse	"Key created — shown once, only a hash is stored"
// @Failure		400	{object}	auth.ErrorMsg	"Invalid JSON body"
// @Failure		403	{object}	auth.ErrorMsg	"Bootstrap disabled, auto-disabled, or setup token invalid"
// @Router			/api-keys/bootstrap [post]
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

	writeJSON(w, bootstrapKeyResponse{
		APIKey:  apiKey,
		Message: "Bootstrap API key generated successfully",
		Note:    note,
	})
}

type generateRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Role        string `json:"role"` // Defaults to admin when omitted
}

type generateKeyResponse struct {
	APIKey      string `json:"api_key"`
	EntityID    int64  `json:"entity_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Role        string `json:"role"`
	Message     string `json:"message"`
}

// @Summary		Generate a new API key
// @Description	Minimum role: admin.
// @Tags			API Keys
// @Accept			json
// @Produce		json
// @Param			body	body	generateRequest	true	"New key name, optional description, and role"
// @Success		200	{object}	generateKeyResponse	"Key created — shown once, only a hash is stored"
// @Failure		400	{object}	auth.ErrorMsg	"Missing name or invalid role"
// @Failure		401	{object}	auth.ErrorMsg	"Missing API key"
// @Failure		403	{object}	auth.ErrorMsg	"Invalid key or insufficient role"
// @Router			/api-keys/generate [post]
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

	writeJSON(w, generateKeyResponse{
		APIKey:      apiKey,
		EntityID:    entity.ID,
		Name:        entity.Name,
		Description: entity.Description,
		Role:        entity.Role,
		Message:     "API key generated successfully",
	})
}

// entityJSON is the sanitized key representation (never the hash).
type entityJSON struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Role        string    `json:"role"` // Authorization role of the key (Agent API v1 role model)
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
}

type listKeysResponse struct {
	Entities []entityJSON `json:"entities"`
	Total    int          `json:"total"`
}

// @Summary		List all API keys
// @Description	Minimum role: admin. Hashes are never returned.
// @Tags			API Keys
// @Produce		json
// @Success		200	{object}	listKeysResponse	"All keys, newest first"
// @Failure		401	{object}	auth.ErrorMsg	"Missing API key"
// @Failure		403	{object}	auth.ErrorMsg	"Invalid key or insufficient role"
// @Router			/api-keys [get]
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
	writeJSON(w, listKeysResponse{
		Entities: entities,
		Total:    len(entities),
	})
}

type keyInfoResponse struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	// "oidc" on SSO-minted keys; absent on plain keys
	AuthProvider string `json:"auth_provider,omitempty"`
	// The federated account's email (SSO-minted keys only)
	Email string `json:"email,omitempty"`
	// The federated account's customer id, from the access token's customer_id claim (SSO-minted keys only)
	CustomerID string `json:"customer_id,omitempty"`
}

// @Summary		Describe the calling key
// @Description	Minimum role: viewer (every valid key may inspect itself). Keys minted by a federated login (device or silent SSO) additionally answer auth_provider ("oidc"), email, and customer_id — the identity read off the validated token at login; plain keys omit all three (the UI consumes fail-open).
// @Tags			API Keys
// @Produce		json
// @Success		200	{object}	keyInfoResponse	"The calling key's attributes"
// @Failure		401	{object}	auth.ErrorMsg	"Missing API key"
// @Failure		403	{object}	auth.ErrorMsg	"Invalid API key"
// @Router			/api-keys/info [get]
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
	response := keyInfoResponse{
		ID:          k.ID,
		Name:        k.Name,
		Description: k.Description,
		Role:        k.Role,
		CreatedAt:   k.CreatedAt,
		LastUsed:    k.LastUsed,
	}
	if ssoIdentity, ok := s.oidcMgr.identityForKey(k.ID); ok {
		response.AuthProvider = "oidc"
		response.Email = ssoIdentity.Email
		response.CustomerID = ssoIdentity.CustomerID
	}
	writeJSON(w, response)
}

type deleteKeyResponse struct {
	Message  string `json:"message"`
	EntityID string `json:"entity_id"`
	Name     string `json:"name"`
}

// @Summary		Permanently delete an API key
// @Description	Minimum role: admin. Deleting the last active admin key is refused (lockout guard).
// @Tags			API Keys
// @Produce		json
// @Param			id	path	int	true	"API key id"
// @Success		200	{object}	deleteKeyResponse	"Key deleted"
// @Failure		404	{object}	auth.ErrorMsg	"No key with that id"
// @Failure		409	{object}	auth.ErrorMsg	"Would remove the last active admin key"
// @Router			/api-keys/{id} [delete]
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

	writeJSON(w, deleteKeyResponse{
		Message:  "API key deleted successfully",
		EntityID: idStr,
		Name:     entity.Name,
	})
}

type revokeKeyResponse struct {
	Message  string `json:"message"`
	EntityID string `json:"entity_id"`
	Name     string `json:"name"`
}

// @Summary		Deactivate an API key
// @Description	Minimum role: admin. Revoking the last active admin key is refused (lockout guard).
// @Tags			API Keys
// @Produce		json
// @Param			id	path	int	true	"API key id"
// @Success		200	{object}	revokeKeyResponse	"Key deactivated"
// @Failure		404	{object}	auth.ErrorMsg	"No key with that id"
// @Failure		409	{object}	auth.ErrorMsg	"Would deactivate the last active admin key"
// @Router			/api-keys/{id}/revoke [put]
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

	writeJSON(w, revokeKeyResponse{
		Message:  "API key revoked successfully",
		EntityID: idStr,
		Name:     entity.Name,
	})
}
