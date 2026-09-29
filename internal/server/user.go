package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"golang.org/x/text/language"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/prefs"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

var themeName = regexp.MustCompile(`^[a-z0-9-]+$`)

type userResponse struct {
	ID                int64    `json:"id"`
	Username          string   `json:"username"`
	Name              string   `json:"name"`
	Email             *string  `json:"email"`
	AuthProvider      *string  `json:"auth_provider"`
	CustomerID        *string  `json:"customer_id"`
	Role              string   `json:"role"`
	Organizations     []string `json:"organizations"`
	PreferredLanguage *string  `json:"preferred_language"`
	PreferredMode     *string  `json:"preferred_mode"`
	PreferredTheme    *string  `json:"preferred_theme"`
	PreferredMotion   *string  `json:"preferred_motion"`
	PreferredTimezone *string  `json:"preferred_timezone"`
}

func (s *Server) personOf(identity *auth.Identity) string {
	if identity == nil {
		return ""
	}
	if minted, ok := s.oidcMgr.IdentityForKey(identity.ID); ok && minted.Email != "" {
		return minted.Email
	}
	return identity.Name
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// @Summary		The signed-in person
// @Description	Minimum role: viewer. The person the calling key stands for, in the identity provider's profile shape the shared UI reads: id, username and name are the key's, email, auth_provider ("oidc") and customer_id come from the federated login that minted the key and are null on a plain key, role is the key's own (admin, operator or viewer), organizations is always empty, and the preferred_* members are the person's stored preferences, null when unset. Preferences are kept per person: by the email of a federated login, else by the key's name.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	userResponse	"The person"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential"
// @Router			/api/user [get]
func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	identity := auth.FromContext(r.Context())
	stored := s.prefs.Get(s.personOf(identity))
	response := userResponse{
		ID:                identity.ID,
		Username:          identity.Name,
		Name:              identity.Name,
		Role:              identity.Role,
		Organizations:     []string{},
		PreferredLanguage: stored.Language,
		PreferredMode:     stored.Mode,
		PreferredTheme:    stored.Theme,
		PreferredMotion:   stored.Motion,
		PreferredTimezone: stored.Timezone,
	}
	if minted, ok := s.oidcMgr.IdentityForKey(identity.ID); ok {
		response.AuthProvider = optional("oidc")
		response.Email = optional(minted.Email)
		response.CustomerID = optional(minted.CustomerID)
	}
	writeJSON(w, response)
}

// @Summary		The signed-in person's preferences
// @Description	Minimum role: viewer. The five members of the branding contract's write path, language, mode, theme, motion and timezone, each null when unset.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	prefs.Preferences	"The preferences"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Router			/api/user/preferences [get]
func (s *Server) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.prefs.Get(s.personOf(auth.FromContext(r.Context()))))
}

func validatePreference(name, value string) *problem.Error {
	var failure problem.Error
	switch name {
	case "language":
		if _, err := language.Parse(value); err != nil {
			failure = problem.Rule("/language", "format", map[string]any{"format": "BCP 47 language tag"})
		}
	case "mode":
		if value != "light" && value != "dark" && value != "auto" {
			failure = problem.Enum("/mode", "light", "dark", "auto")
		}
	case "theme":
		if !themeName.MatchString(value) {
			failure = problem.Pattern("/theme", themeName.String())
		}
	case "motion":
		if value != "auto" && value != "reduce" {
			failure = problem.Enum("/motion", "auto", "reduce")
		}
	case "timezone":
		if _, err := time.LoadLocation(value); err != nil || value == "Local" {
			failure = problem.Rule("/timezone", "format", map[string]any{"format": "IANA time zone"})
		}
	}
	if failure.Rule == "" {
		return nil
	}
	return &failure
}

type preferencePatchRequest struct {
	Language *string `json:"language"`
	Mode     *string `json:"mode"`
	Theme    *string `json:"theme"`
	Motion   *string `json:"motion"`
	Timezone *string `json:"timezone"`
}

func decodePreferencePatch(r *http.Request) (map[string]*string, []problem.Error, bool) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body == nil {
		return nil, nil, false
	}
	patch := map[string]*string{}
	failures := []problem.Error{}
	for key, raw := range body {
		known := false
		for _, member := range prefs.Members {
			if key == member {
				known = true
			}
		}
		if !known {
			failures = append(failures, problem.Rule("/"+key, "not", nil))
			continue
		}
		if string(raw) == "null" {
			patch[key] = nil
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			failures = append(failures, problem.Rule("/"+key, "type", map[string]any{"type": "string"}))
			continue
		}
		if value == "" {
			patch[key] = nil
			continue
		}
		if failure := validatePreference(key, value); failure != nil {
			failures = append(failures, *failure)
			continue
		}
		patch[key] = &value
	}
	return patch, failures, true
}

// @Summary		Write the signed-in person's preferences
// @Description	Minimum role: viewer. A merge over the five members language, mode, theme, motion and timezone: a sent member replaces the stored value, an omitted member is unchanged, null or "" clears one. Validation: language a well-formed BCP 47 tag, mode light, dark or auto, theme a bare pack name matching ^[a-z0-9-]+$, motion auto or reduce, timezone an IANA zone id; a violation answers 422 with a pointer per failing member and nothing is written. When a stored value changed, profile-updated is sent on the profile topic of the stream to this person alone. Answers the preferences as stored.
// @Tags			Local Login
// @Accept			json
// @Produce		json
// @Param			body	body		preferencePatchRequest	true	"The members to change"
// @Success		200		{object}	prefs.Preferences		"The preferences as stored"
// @Failure		400		{object}	problem.Body			"Unreadable body"
// @Failure		401		{object}	problem.Body			"Missing credential"
// @Failure		422		{object}	problem.Body			"A member fails its rule, or is not a preference"
// @Router			/api/user/preferences [patch]
func (s *Server) handlePatchPreferences(w http.ResponseWriter, r *http.Request) {
	patch, failures, ok := decodePreferencePatch(r)
	if !ok {
		problem.BadRequest(w)
		return
	}
	if len(failures) > 0 {
		problem.Invalid(w, failures...)
		return
	}
	person := s.personOf(auth.FromContext(r.Context()))
	stored, changed, err := s.prefs.Apply(person, patch)
	if err != nil {
		slog.Error("preference write failed", "error", err, "person", person)
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	if changed {
		s.publishProfileUpdated(person)
	}
	writeJSON(w, stored)
}
