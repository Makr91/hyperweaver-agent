package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ErrExchangeRefused is answered when the identity provider refuses to exchange the held token for a resource.
var ErrExchangeRefused = errors.New("the identity provider refused the token exchange")

type resourceToken struct {
	accessToken string
	expiry      time.Time
}

type tokenSource struct {
	mu           sync.Mutex
	provider     *provider
	clientID     string
	scope        string
	ctx          context.Context
	wg           *sync.WaitGroup
	persist      func(refreshToken string)
	accessToken  string
	refreshToken string
	expiry       time.Time
	refreshing   bool
	resources    map[string]resourceToken
}

func (t *tokenSource) bearer() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.accessToken == "" || time.Now().After(t.expiry) {
		return ""
	}
	return t.accessToken
}

func (t *tokenSource) tokenFor(ctx context.Context, resource string) (string, error) {
	t.mu.Lock()
	cached, held := t.resources[resource]
	subject := t.accessToken
	if time.Now().After(t.expiry) {
		subject = ""
	}
	t.mu.Unlock()
	if held && time.Now().Before(cached.expiry) {
		return cached.accessToken, nil
	}
	if subject == "" {
		return "", nil
	}
	endpoints, err := t.provider.endpoints(ctx)
	if err != nil {
		return "", err
	}
	answer, err := exchangeToken(ctx, endpoints, t.clientID, subject, resource, t.scope)
	if err != nil {
		return "", err
	}
	if answer.Error != "" || answer.AccessToken == "" {
		return "", fmt.Errorf("%w for %s: %s", ErrExchangeRefused, resource, answer.refusal())
	}
	t.mu.Lock()
	if t.resources == nil {
		t.resources = map[string]resourceToken{}
	}
	t.resources[resource] = resourceToken{
		accessToken: answer.AccessToken,
		expiry:      time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second),
	}
	t.mu.Unlock()
	return answer.AccessToken, nil
}

func (t *tokenSource) forget(resource string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.resources, resource)
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
	t.resources = nil
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
