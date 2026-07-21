package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

const oidcSilentTTL = 5 * time.Minute

type oidcSilentFlow struct {
	verifier  string
	expiresAt time.Time
}

func (m *oidcManager) startSilent(ctx context.Context) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	endpoints, err := m.cachedEndpoints(probeCtx)
	if err != nil {
		return "", err
	}
	if endpoints.Authorization == "" {
		return "", errors.New("issuer discovery document carries no authorization_endpoint")
	}

	rawVerifier := make([]byte, 64)
	if _, rerr := rand.Read(rawVerifier); rerr != nil {
		return "", rerr
	}
	verifier := base64.RawURLEncoding.EncodeToString(rawVerifier)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	rawState := make([]byte, 32)
	if _, rerr := rand.Read(rawState); rerr != nil {
		return "", rerr
	}
	state := hex.EncodeToString(rawState)

	m.mu.Lock()
	for existing, entry := range m.silent {
		if time.Now().After(entry.expiresAt) {
			delete(m.silent, existing)
		}
	}
	m.silent[state] = &oidcSilentFlow{verifier: verifier, expiresAt: time.Now().Add(oidcSilentTTL)}
	m.mu.Unlock()

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {m.clientID},
		"redirect_uri":          {m.redirectURI},
		"scope":                 {m.scope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"none"},
	}
	return endpoints.Authorization + "?" + query.Encode(), nil
}

func (m *oidcManager) exchangeSilent(ctx context.Context, state, code string) (*oidcCredential, error) {
	m.mu.Lock()
	flow := m.silent[state]
	delete(m.silent, state)
	m.mu.Unlock()
	if flow == nil || time.Now().After(flow.expiresAt) {
		return nil, errors.New("unknown or expired state")
	}

	endpoints, err := m.cachedEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	answer, err := oidcExchangeCode(ctx, endpoints, m.clientID, code, m.redirectURI, flow.verifier)
	if err != nil {
		return nil, err
	}
	if answer.Error != "" {
		return nil, errors.New("code exchange refused: " + answer.Error)
	}
	if answer.AccessToken == "" {
		return nil, errors.New("code exchange answered no access token")
	}

	jwks, err := m.cachedJWKS(false)
	if err != nil {
		return nil, err
	}
	identityToken := answer.IDToken
	if identityToken == "" {
		identityToken = answer.AccessToken
	}
	claims, err := oidcValidateToken(identityToken, jwks, m.issuer, m.clientID)
	if errors.Is(err, errOIDCUnknownKey) {
		if jwks, err = m.cachedJWKS(true); err == nil {
			claims, err = oidcValidateToken(identityToken, jwks, m.issuer, m.clientID)
		}
	}
	if err != nil {
		return nil, err
	}
	if !m.subjectAllowed(claims) {
		return nil, errors.New("account is not the bound account and not in oidc.allowed_users")
	}
	return m.completeLogin(claims, answer)
}

type silentStartResponse struct {
	// The IdP authorize URL (response_type=code, loopback redirect_uri, S256 PKCE challenge, prompt=none) — navigate the browser here; the agent holds the state and verifier
	AuthorizeURL string `json:"authorize_url"`
}

// @Summary		Start a silent SSO pre-check
// @Description	Public, rate-limited (shared with device-start: 6 per source address per minute). The identity-first login probe (a Go-agent-only surface): mints state + a PKCE S256 verifier held agent-side and answers the IdP authorize URL with prompt=none — the UI navigates there; a live IdP session comes straight back to GET /auth/oidc/callback with a code and signs in without any interaction, no session bounces back benignly. NEVER auto-fires anything — this endpoint only returns a URL. Fast-fails when the identity provider is unreachable (cached discovery; a cold probe is bounded to ~3s) so an offline machine loses milliseconds, never hangs.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	silentStartResponse	"Authorize URL minted"
// @Failure		429	{object}	taskErrorBody	"Too many attempts from this address"
// @Failure		502	{object}	taskErrorBody	"Identity provider unreachable or without an authorization endpoint"
// @Failure		503	{object}	taskErrorBody	"OIDC login is disabled"
// @Router			/auth/oidc/silent-start [post]
func (s *Server) handleOIDCSilentStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.OIDC.Enabled {
		taskError(w, http.StatusServiceUnavailable, "OIDC login is disabled")
		return
	}
	if !s.oidcStarts.allow(r.RemoteAddr) {
		taskError(w, http.StatusTooManyRequests, "Too many login attempts — try again in a minute")
		return
	}
	authorizeURL, err := s.oidcMgr.startSilent(r.Context())
	if err != nil {
		slog.Warn("oidc silent start failed", "error", err)
		taskError(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
		return
	}
	writeJSON(w, silentStartResponse{AuthorizeURL: authorizeURL})
}

// @Summary		Silent SSO callback
// @Description	Browser redirect target of the silent authorize round-trip (registered at the IdP as the loopback redirect_uri) — never called by API clients. Benign IdP answers (login_required, interaction_required, consent_required, access_denied) and EVERY hard failure (unknown/expired state, exchange or validation error, non-bound account) all 302 to /ui/login?sso=unavailable — silent must never strand the browser on an error page. On success the code is exchanged with the held PKCE verifier, the token validated (issuer JWKS, UUID-first identity, TOFU binding), the OIDC admin key minted, and the browser 302s to the existing /ui/#tray= claim path carrying a single-use grant that answers THAT key — the tray-claim exchange the UI already speaks, now with a federated identity.
// @Tags			Local Login
// @Param			state	query	string	false	"The flow id minted at silent-start"
// @Param			code	query	string	false	"The IdP's authorization code"
// @Param			error	query	string	false	"The IdP's OAuth error (login_required and friends bounce benignly)"
// @Success		302	"To /ui/#tray=<one-time grant> on success; to /ui/login?sso=unavailable otherwise"
// @Router			/auth/oidc/callback [get]
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	unavailable := func() {
		http.Redirect(w, r, "/ui/login?sso=unavailable", http.StatusFound)
	}
	if !s.cfg.OIDC.Enabled {
		unavailable()
		return
	}
	query := r.URL.Query()
	if oauthError := query.Get("error"); oauthError != "" {
		slog.Info("oidc silent probe answered without a session", "error", oauthError)
		unavailable()
		return
	}
	state, code := query.Get("state"), query.Get("code")
	if state == "" || code == "" {
		unavailable()
		return
	}
	credential, err := s.oidcMgr.exchangeSilent(r.Context(), state, code)
	if err != nil {
		slog.Warn("oidc silent callback failed", "error", err)
		unavailable()
		return
	}
	grant, err := s.trayTokens.MintForKey(credential.apiKey)
	if err != nil {
		slog.Error("oidc silent handoff mint failed", "error", err)
		unavailable()
		return
	}
	slog.Info("oidc silent login succeeded", "entity_id", credential.entityID, "name", credential.name)
	http.Redirect(w, r, "/ui/#tray="+grant, http.StatusFound)
}
