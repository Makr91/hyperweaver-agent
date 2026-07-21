package server

import (
	"log/slog"
	"time"
)

func (m *oidcManager) startRefreshLoop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refreshing || m.refreshToken == "" {
		return
	}
	m.refreshing = true
	m.wg.Add(1)
	go m.refreshLoop()
}

func (m *oidcManager) refreshLoop() {
	defer m.wg.Done()
	for {
		m.mu.Lock()
		refreshToken := m.refreshToken
		expiresAt := m.tokenExpiry
		m.mu.Unlock()
		if refreshToken == "" {
			m.mu.Lock()
			m.refreshing = false
			m.mu.Unlock()
			return
		}
		wait := time.Until(expiresAt) - time.Minute
		if wait < 30*time.Second {
			wait = 30 * time.Second
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(wait):
		}
		if !m.refreshOnce(refreshToken) {
			return
		}
	}
}

func (m *oidcManager) refreshOnce(refreshToken string) bool {
	endpoints, err := oidcDiscover(m.ctx, m.issuer)
	if err != nil {
		slog.Warn("oidc refresh: discovery failed — retrying in 5m", "error", err)
		return m.refreshBackoff()
	}
	answer, err := oidcRefreshTokens(m.ctx, endpoints, m.clientID, refreshToken)
	if err != nil {
		slog.Warn("oidc refresh failed — retrying in 5m", "error", err)
		return m.refreshBackoff()
	}
	if answer.Error == "invalid_grant" {
		slog.Warn("oidc refresh token revoked — log in again to restore federated access")
		m.mu.Lock()
		m.accessToken = ""
		m.refreshToken = ""
		m.tokenExpiry = time.Time{}
		m.refreshing = false
		m.mu.Unlock()
		return false
	}
	if answer.Error != "" || answer.AccessToken == "" {
		slog.Warn("oidc refresh refused — retrying in 5m", "error", answer.Error)
		return m.refreshBackoff()
	}
	m.mu.Lock()
	m.accessToken = answer.AccessToken
	if answer.RefreshToken != "" {
		m.refreshToken = answer.RefreshToken
	}
	m.tokenExpiry = time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	m.mu.Unlock()
	return true
}

func (m *oidcManager) refreshBackoff() bool {
	select {
	case <-m.ctx.Done():
		return false
	case <-time.After(5 * time.Minute):
		return true
	}
}
