package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/oidc"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

const (
	favoritesPath   = "/api/user/favorites"
	issuerBodyLimit = 1 << 20
)

type favoriteWrite struct {
	ClientID    string `json:"client_id"`
	CustomLabel string `json:"custom_label"`
	Order       int    `json:"order"`
}

func (s *Server) relayIssuer(w http.ResponseWriter, r *http.Request, path string, body io.Reader) (int, bool) {
	identity := auth.FromContext(r.Context())
	if _, bound := s.oidcMgr.IdentityForKey(identity.ID); !bound {
		problem.NotFound(w)
		return 0, false
	}
	response, err := s.oidcMgr.IssuerRequest(r.Context(), r.Method, path, body, r.Header.Get("Content-Type"))
	if errors.Is(err, oidc.ErrNoToken) {
		problem.Detail(w, http.StatusServiceUnavailable, "The agent holds no valid token for the bound account; sign in again")
		return 0, false
	}
	if err != nil {
		slog.Warn("issuer relay failed", "error", err, "method", r.Method, "path", path)
		problem.Detail(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
		return 0, false
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(response.StatusCode)
	if _, cerr := io.Copy(w, io.LimitReader(response.Body, issuerBodyLimit)); cerr != nil {
		slog.Warn("issuer relay write failed", "error", cerr, "path", path)
	}
	return response.StatusCode, true
}

// @Summary		The signed-in person's favorites
// @Description	Minimum role: viewer. Relayed to the identity provider's GET /api/user/favorites under the bound account's token, the way a backend host proxies it, so the user menu draws the same list on every host; the issuer's status and body are answered as they came. A key no federated login minted answers 404, and an agent holding no valid token for its bound account answers 503. The favorites token is listed in status.features only while such a token is held.
// @Tags			Local Login
// @Produce		json
// @Success		200	{array}		map[string]interface{}	"The ordered favorites, each {client_id, client_name, icon_url, home_url, custom_label, order}"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/user/favorites [get]
func (s *Server) handleGetFavorites(w http.ResponseWriter, r *http.Request) {
	s.relayIssuer(w, r, favoritesPath, http.NoBody)
}

// @Summary		Save the signed-in person's favorites
// @Description	Minimum role: viewer. The whole ordered list, relayed to the identity provider's PUT /api/user/favorites under the bound account's token; the issuer answers the enriched entries from each client's registration, and its status and body are answered as they came.
// @Tags			Local Login
// @Accept			json
// @Produce		json
// @Param			body	body		[]favoriteWrite	true	"The whole ordered list"
// @Success		200		{array}		map[string]interface{}	"The favorites as stored, each {client_id, client_name, icon_url, home_url, custom_label, order}"
// @Failure		400		{object}	problem.Body	"The body is not a JSON array of entries"
// @Failure		404		{object}	problem.Body	"The calling key was not minted by a federated login"
// @Failure		502		{object}	problem.Body	"Identity provider unreachable"
// @Failure		503		{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/user/favorites [put]
func (s *Server) handlePutFavorites(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, issuerBodyLimit))
	if err != nil {
		problem.BadRequest(w)
		return
	}
	var list []favoriteWrite
	if json.Unmarshal(raw, &list) != nil {
		problem.BadRequest(w)
		return
	}
	s.relayIssuer(w, r, favoritesPath, bytes.NewReader(raw))
}
