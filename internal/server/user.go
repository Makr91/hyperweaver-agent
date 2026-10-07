package server

import (
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
)

type userResponse struct {
	ID                int64    `json:"id"`
	Username          string   `json:"username"`
	Name              string   `json:"name"`
	Email             *string  `json:"email"`
	AuthProvider      *string  `json:"auth_provider"`
	CustomerID        *string  `json:"customer_id"`
	Issuer            *string  `json:"issuer"`
	Subject           *string  `json:"subject"`
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
	return s.personOfKey(identity.ID, identity.Name)
}

func (s *Server) personOfKey(id int64, name string) string {
	if minted, ok := s.oidcMgr.IdentityForKey(id); ok && minted.Email != "" {
		return minted.Email
	}
	return name
}

func (s *Server) personsOfActiveKeys() []string {
	seen := map[string]bool{}
	persons := []string{}
	for _, k := range s.keys.List() {
		if !k.IsActive {
			continue
		}
		person := s.personOfKey(k.ID, k.Name)
		if person == "" || seen[person] {
			continue
		}
		seen[person] = true
		persons = append(persons, person)
	}
	return persons
}

func (s *Server) personsOfKeyName(name string) []string {
	person := ""
	for _, k := range s.keys.List() {
		if !k.IsActive || k.Name != name {
			continue
		}
		if minted, ok := s.oidcMgr.IdentityForKey(k.ID); ok && minted.Email != "" {
			return []string{minted.Email}
		}
		person = k.Name
	}
	if person != "" {
		return []string{person}
	}
	return s.personsOfActiveKeys()
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// @Summary		The signed-in person
// @Description	Minimum role: viewer. The person the calling key stands for, in the identity provider's profile shape the shared UI reads: id, username and name are the key's, email, auth_provider ("oidc"), customer_id, issuer and subject come from the federated login that minted the key and are null on a plain key, role is the key's own (admin, operator or viewer), organizations is always empty, and the preferred_* members are always null, the agent keeping no preferences; the browser keeps them.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	userResponse	"The person"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential"
// @Router			/api/user [get]
func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	identity := auth.FromContext(r.Context())
	response := userResponse{
		ID:            identity.ID,
		Username:      identity.Name,
		Name:          identity.Name,
		Role:          identity.Role,
		Organizations: []string{},
	}
	if minted, ok := s.oidcMgr.IdentityForKey(identity.ID); ok {
		response.AuthProvider = optional("oidc")
		response.Email = optional(minted.Email)
		response.CustomerID = optional(minted.CustomerID)
		response.Issuer = optional(s.oidcMgr.Issuer())
		response.Subject = optional(minted.Subject)
	}
	writeJSON(w, response)
}
