package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// The refusals of a pasted code.
var (
	ErrUnknownHandle  = errors.New("unknown login handle")
	ErrFlowNotPending = errors.New("the login is no longer pending")
	ErrStateMismatch  = errors.New("the pasted state is not this login's")
)

type codeFlow struct {
	verifier    string
	callbackURI string
	codePageURI string
	handle      string
	expiresAt   time.Time
}

func (c *client) startCode(ctx context.Context, loopback bool) (handle, authorizeURL, manualURL string, expiresIn int, err error) {
	endpoints, err := c.provider.endpoints(ctx)
	if err != nil {
		return "", "", "", 0, err
	}
	if endpoints.Authorization == "" {
		return "", "", "", 0, errors.New("issuer discovery document carries no authorization_endpoint")
	}
	verifier, challenge, err := pkcePair()
	if err != nil {
		return "", "", "", 0, err
	}
	state, err := randomHex()
	if err != nil {
		return "", "", "", 0, err
	}
	handle, err = randomHex()
	if err != nil {
		return "", "", "", 0, err
	}
	codePageURI := strings.TrimRight(c.provider.issuer, "/") + "/oauth2/code"
	now := time.Now()
	expiresAt := now.Add(silentTTL)

	c.mu.Lock()
	for existing, entry := range c.codeFlows {
		if now.After(entry.expiresAt) {
			delete(c.codeFlows, existing)
		}
	}
	c.sweepFlowsLocked()
	c.codeFlows[state] = &codeFlow{
		verifier:    verifier,
		callbackURI: c.redirectURI,
		codePageURI: codePageURI,
		handle:      handle,
		expiresAt:   expiresAt,
	}
	c.flows[handle] = &flow{
		status:    StatusPending,
		expiresAt: expiresAt,
		interval:  time.Until(expiresAt),
		changed:   make(chan struct{}),
	}
	c.mu.Unlock()

	authorize := func(redirectURI string) string {
		query := url.Values{
			"response_type":         {"code"},
			"client_id":             {c.clientID},
			"redirect_uri":          {redirectURI},
			"scope":                 {c.scope},
			"state":                 {state},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		return endpoints.Authorization + "?" + query.Encode()
	}
	manualURL = authorize(codePageURI)
	authorizeURL = manualURL
	if loopback {
		authorizeURL = authorize(c.redirectURI)
	}
	return handle, authorizeURL, manualURL, int(silentTTL / time.Second), nil
}

func (c *client) codeFlowHandle(state string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.codeFlows[state]
	if entry == nil {
		return "", false
	}
	return entry.handle, true
}

func (c *client) refuseCode(state, status string) {
	c.mu.Lock()
	entry := c.codeFlows[state]
	delete(c.codeFlows, state)
	c.mu.Unlock()
	if entry != nil {
		c.setStatus(entry.handle, status)
	}
}

func (c *client) exchangeCodeFlow(ctx context.Context, state, code string) (*Credential, error) {
	c.mu.Lock()
	pending := c.codeFlows[state]
	delete(c.codeFlows, state)
	c.mu.Unlock()
	if pending == nil || time.Now().After(pending.expiresAt) {
		return nil, errors.New("unknown or expired state")
	}
	credential, _, err := c.redeemCodeFlow(ctx, pending, code, pending.callbackURI)
	return credential, err
}

func (c *client) submitCode(ctx context.Context, handle, code, state string) (string, error) {
	c.mu.Lock()
	entry := c.flows[handle]
	if entry == nil {
		c.mu.Unlock()
		return "", ErrUnknownHandle
	}
	if entry.status != StatusPending || time.Now().After(entry.expiresAt) {
		c.mu.Unlock()
		return "", ErrFlowNotPending
	}
	var pending *codeFlow
	var key string
	for existing, candidate := range c.codeFlows {
		if candidate.handle == handle {
			pending, key = candidate, existing
			break
		}
	}
	if pending == nil {
		c.mu.Unlock()
		return "", ErrUnknownHandle
	}
	if state != "" && state != key {
		c.mu.Unlock()
		return "", ErrStateMismatch
	}
	delete(c.codeFlows, key)
	c.mu.Unlock()
	_, status, _ := c.redeemCodeFlow(ctx, pending, code, pending.codePageURI)
	return status, nil
}

func (c *client) redeemCodeFlow(ctx context.Context, pending *codeFlow, code, redirectURI string) (*Credential, string, error) {
	credential, err := c.redeemCode(ctx, code, redirectURI, pending.verifier)
	if err != nil {
		status := StatusFailed
		if errors.Is(err, errNotAllowed) {
			status = StatusDenied
		}
		slog.Warn("oidc code login failed", "error", err)
		c.setStatus(pending.handle, status)
		return nil, status, err
	}
	c.approve(pending.handle, credential)
	slog.Info("oidc code login succeeded", "entity_id", credential.EntityID, "name", credential.Name)
	return credential, StatusApproved, nil
}
