package oidc

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type tokenSource struct {
	mu           sync.Mutex
	provider     *provider
	clientID     string
	ctx          context.Context
	wg           *sync.WaitGroup
	persist      func(refreshToken string)
	accessToken  string
	refreshToken string
	expiry       time.Time
	refreshing   bool
}

func (t *tokenSource) bearer() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.accessToken == "" || time.Now().After(t.expiry) {
		return ""
	}
	return t.accessToken
}

func (t *tokenSource) set(answer *tokenAnswer) {
	t.mu.Lock()
	t.accessToken = answer.AccessToken
	if answer.RefreshToken != "" {
		t.refreshToken = answer.RefreshToken
	}
	t.expiry = time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	refreshToken := t.refreshToken
	t.mu.Unlock()
	t.persist(refreshToken)
	t.startRefreshLoop()
}

func (t *tokenSource) resume(refreshToken string) {
	if refreshToken == "" {
		return
	}
	t.mu.Lock()
	t.refreshToken = refreshToken
	t.refreshing = true
	t.mu.Unlock()
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		if t.refreshOnce(refreshToken) {
			t.loop()
		}
	}()
}

func (t *tokenSource) startRefreshLoop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.refreshing || t.refreshToken == "" {
		return
	}
	t.refreshing = true
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.loop()
	}()
}

func (t *tokenSource) loop() {
	for {
		t.mu.Lock()
		refreshToken := t.refreshToken
		expiresAt := t.expiry
		t.mu.Unlock()
		if refreshToken == "" {
			t.mu.Lock()
			t.refreshing = false
			t.mu.Unlock()
			return
		}
		wait := time.Until(expiresAt) - time.Minute
		if wait < 30*time.Second {
			wait = 30 * time.Second
		}
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(wait):
		}
		if !t.refreshOnce(refreshToken) {
			return
		}
	}
}

func (t *tokenSource) refreshOnce(refreshToken string) bool {
	endpoints, err := t.provider.endpoints(t.ctx)
	if err != nil {
		slog.Warn("oidc refresh: discovery failed — retrying in 5m", "error", err)
		return t.refreshBackoff()
	}
	answer, err := refreshTokens(t.ctx, endpoints, t.clientID, refreshToken)
	if err != nil {
		slog.Warn("oidc refresh failed — retrying in 5m", "error", err)
		return t.refreshBackoff()
	}
	if answer.Error == "invalid_grant" {
		slog.Warn("oidc refresh token revoked — log in again to restore federated access")
		t.clear()
		return false
	}
	if answer.Error != "" || answer.AccessToken == "" {
		slog.Warn("oidc refresh refused — retrying in 5m", "error", answer.Error)
		return t.refreshBackoff()
	}
	t.mu.Lock()
	t.accessToken = answer.AccessToken
	if answer.RefreshToken != "" {
		t.refreshToken = answer.RefreshToken
	}
	t.expiry = time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	rotated := t.refreshToken
	t.mu.Unlock()
	t.persist(rotated)
	return true
}

func (t *tokenSource) clear() {
	t.mu.Lock()
	t.accessToken = ""
	t.refreshToken = ""
	t.expiry = time.Time{}
	t.refreshing = false
	t.mu.Unlock()
	t.persist("")
}

func (t *tokenSource) refreshBackoff() bool {
	select {
	case <-t.ctx.Done():
		return false
	case <-time.After(5 * time.Minute):
		return true
	}
}
