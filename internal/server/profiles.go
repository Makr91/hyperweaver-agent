package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// Provisioning profile endpoints — the base's ProvisioningProfileController:
// reusable bundles of credentials/folders/provisioners/variables the user
// composes without bundling a Hosts.yml or provisioner package. The UI
// applies a profile by feeding its pieces into a machine's provisioner
// document (PUT /machines/{name}).

// profileBody is the create/update request shape (the base's field set minus
// the zlogin-only recipe_id).
type profileBody struct {
	Name                *string         `json:"name"`
	Description         *string         `json:"description"`
	DefaultCredentials  json.RawMessage `json:"default_credentials"`
	DefaultSyncFolders  json.RawMessage `json:"default_sync_folders"`
	DefaultProvisioners json.RawMessage `json:"default_provisioners"`
	DefaultVariables    json.RawMessage `json:"default_variables"`
}

// handleListProfiles mirrors GET /provisioning/profiles.
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.machines.ListProfiles(r.Context())
	if err != nil {
		slog.Error("list provisioning profiles", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list provisioning profiles")
		return
	}
	writeJSON(w, map[string]any{
		"success":  true,
		"count":    len(profiles),
		"profiles": profiles,
	})
}

// handleCreateProfile mirrors POST /provisioning/profiles (201; 409 on a name
// collision).
func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var body profileBody
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == nil || *body.Name == "" {
		taskError(w, http.StatusBadRequest, "name is required")
		return
	}

	profile := &machines.Profile{
		Name:                *body.Name,
		DefaultCredentials:  body.DefaultCredentials,
		DefaultSyncFolders:  body.DefaultSyncFolders,
		DefaultProvisioners: body.DefaultProvisioners,
		DefaultVariables:    body.DefaultVariables,
		CreatedBy:           auth.FromContext(r.Context()).Name,
	}
	if body.Description != nil {
		profile.Description = *body.Description
	}
	created, err := s.machines.CreateProfile(r.Context(), profile)
	if errors.Is(err, machines.ErrProfileExists) {
		taskError(w, http.StatusConflict, "Profile '"+*body.Name+"' already exists")
		return
	}
	if err != nil {
		slog.Error("create provisioning profile", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create provisioning profile")
		return
	}
	slog.Info("provisioning profile created", "id", created.ID, "name", created.Name)
	writeJSONStatus(w, http.StatusCreated, map[string]any{"success": true, "profile": created})
}

// findProfile loads a profile by the {profileId} path value (nil = response
// already written).
func (s *Server) findProfile(w http.ResponseWriter, r *http.Request) *machines.Profile {
	id, err := strconv.ParseInt(r.PathValue("profileId"), 10, 64)
	if err != nil {
		taskError(w, http.StatusNotFound, "Profile not found")
		return nil
	}
	profile, err := s.machines.GetProfile(r.Context(), id)
	if errors.Is(err, machines.ErrProfileNotFound) {
		taskError(w, http.StatusNotFound, "Profile not found")
		return nil
	}
	if err != nil {
		slog.Error("get provisioning profile", "id", id, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to get provisioning profile")
		return nil
	}
	return profile
}

// handleGetProfile mirrors GET /provisioning/profiles/{id}.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	profile := s.findProfile(w, r)
	if profile == nil {
		return
	}
	writeJSON(w, map[string]any{"success": true, "profile": profile})
}

// handleUpdateProfile mirrors PUT /provisioning/profiles/{id}: only submitted
// fields change (the base's allowed-fields merge).
func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	profile := s.findProfile(w, r)
	if profile == nil {
		return
	}
	var body profileBody
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name != nil && *body.Name != "" {
		profile.Name = *body.Name
	}
	if body.Description != nil {
		profile.Description = *body.Description
	}
	if body.DefaultCredentials != nil {
		profile.DefaultCredentials = body.DefaultCredentials
	}
	if body.DefaultSyncFolders != nil {
		profile.DefaultSyncFolders = body.DefaultSyncFolders
	}
	if body.DefaultProvisioners != nil {
		profile.DefaultProvisioners = body.DefaultProvisioners
	}
	if body.DefaultVariables != nil {
		profile.DefaultVariables = body.DefaultVariables
	}

	updated, err := s.machines.UpdateProfile(r.Context(), profile)
	if err != nil {
		slog.Error("update provisioning profile", "id", profile.ID, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update provisioning profile")
		return
	}
	slog.Info("provisioning profile updated", "id", updated.ID, "name", updated.Name)
	writeJSON(w, map[string]any{"success": true, "profile": updated})
}

// handleDeleteProfile mirrors DELETE /provisioning/profiles/{id}.
func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	profile := s.findProfile(w, r)
	if profile == nil {
		return
	}
	if err := s.machines.DeleteProfile(r.Context(), profile.ID); err != nil {
		slog.Error("delete provisioning profile", "id", profile.ID, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to delete provisioning profile")
		return
	}
	slog.Info("provisioning profile deleted", "id", profile.ID, "name", profile.Name)
	writeJSON(w, map[string]any{"success": true, "message": "Profile '" + profile.Name + "' deleted"})
}
