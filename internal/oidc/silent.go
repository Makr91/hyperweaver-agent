package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"time"
)

const silentTTL = 5 * time.Minute

type silentFlow struct {
	verifier  string
	expiresAt time.Time
}

// StartSilent mints a state and PKCE verifier and answers the issuer's prompt=none authorize URL.
func (m *Manager) StartSilent(ctx context.Context) (string, error) {
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
	m.silent[state] = &silentFlow{verifier: verifier, expiresAt: time.Now().Add(silentTTL)}
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

// ExchangeSilent trades the callback's code for tokens with the held verifier and completes the login.
func (m *Manager) ExchangeSilent(ctx context.Context, state, code string) (*Credential, error) {
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
	answer, err := exchangeCode(ctx, endpoints, m.clientID, code, m.redirectURI, flow.verifier)
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
	claims, err := validateToken(identityToken, jwks, m.issuer, m.clientID)
	if errors.Is(err, errUnknownKey) {
		if jwks, err = m.cachedJWKS(true); err == nil {
			claims, err = validateToken(identityToken, jwks, m.issuer, m.clientID)
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
