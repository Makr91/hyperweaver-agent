package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/keys"
)

const (
	keyDescriptionPrefix = "Created by OIDC device login "
	mintedKeysKept       = 5
	silentTTL            = 5 * time.Minute
)

// Credential is the local API key a completed login minted.
type Credential struct {
	EntityID int64
	Name     string
	Role     string
}

type flow struct {
	status     string
	credential *Credential
	expiresAt  time.Time
	interval   time.Duration
	changed    chan struct{}
}

type silentFlow struct {
	verifier  string
	expiresAt time.Time
}

type client struct {
	mu          sync.Mutex
	provider    *provider
	binding     *binding
	tokens      *tokenSource
	keys        *keys.Store
	ctx         context.Context
	wg          *sync.WaitGroup
	clientID    string
	scope       string
	deviceScope string
	redirectURI string
	hashRounds  int
	keyLength   int
	flows       map[string]*flow
	silent      map[string]*silentFlow
	codeFlows   map[string]*codeFlow
}

var errNotAllowed = errors.New("account is not the bound account and not in oidc.allowed_users")

func randomHex() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func pkcePair() (verifier, challenge string, err error) {
	rawVerifier := make([]byte, 64)
	if _, err = rand.Read(rawVerifier); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(rawVerifier)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func (c *client) sweepFlowsLocked() {
	for existing, entry := range c.flows {
		if time.Now().After(entry.expiresAt.Add(10 * time.Minute)) {
			delete(c.flows, existing)
		}
	}
}

func (c *client) start(ctx context.Context) (string, *DeviceAuthorization, error) {
	endpoints, err := discover(ctx, c.provider.issuer)
	if err != nil {
		return "", nil, err
	}
	authorization, err := startDeviceAuthorization(ctx, endpoints, c.clientID, c.deviceScope)
	if err != nil {
		return "", nil, err
	}
	handle, err := randomHex()
	if err != nil {
		return "", nil, err
	}
	expiresAt := time.Now().Add(time.Duration(authorization.ExpiresIn) * time.Second)

	c.mu.Lock()
	c.sweepFlowsLocked()
	c.flows[handle] = &flow{
		status:    StatusPending,
		expiresAt: expiresAt,
		interval:  time.Duration(authorization.Interval) * time.Second,
		changed:   make(chan struct{}),
	}
	c.mu.Unlock()

	c.wg.Add(1)
	go c.watch(handle, endpoints, authorization, expiresAt)

	return handle, authorization, nil
}

func (c *client) await(ctx context.Context, handle string) {
	c.mu.Lock()
	entry := c.flows[handle]
	if entry == nil || entry.status != StatusPending {
		c.mu.Unlock()
		return
	}
	changed := entry.changed
	interval := entry.interval
	c.mu.Unlock()
	select {
	case <-changed:
	case <-ctx.Done():
	case <-time.After(interval):
	}
}

func (c *client) status(handle string) (string, *Credential, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.flows[handle]
	if entry == nil {
		return "", nil, false
	}
	switch entry.status {
	case StatusApproved:
		credential := entry.credential
		delete(c.flows, handle)
		return StatusApproved, credential, true
	case StatusExpired:
		delete(c.flows, handle)
		return StatusExpired, nil, true
	case StatusPending:
		if time.Now().After(entry.expiresAt) {
			delete(c.flows, handle)
			return StatusExpired, nil, true
		}
		return StatusPending, nil, true
	default:
		return entry.status, nil, true
	}
}

func (c *client) approve(handle string, credential *Credential) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.flows[handle]; entry != nil && entry.status == StatusPending {
		entry.status = StatusApproved
		entry.credential = credential
		close(entry.changed)
	}
}

func (c *client) setStatus(handle, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry := c.flows[handle]; entry != nil && entry.status == StatusPending {
		entry.status = status
		close(entry.changed)
	}
}

func (c *client) watch(handle string, endpoints *providerEndpoints, authorization *DeviceAuthorization, deadline time.Time) {
	defer c.wg.Done()
	interval := time.Duration(authorization.Interval) * time.Second
	for {
		wait := interval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(wait):
		}
		if time.Now().After(deadline) {
			c.setStatus(handle, StatusExpired)
			return
		}
		answer, err := pollToken(c.ctx, endpoints, c.clientID, authorization.DeviceCode)
		if err != nil {
			interval *= 2
			slog.Warn("oidc token poll failed — retrying", "error", err, "next_poll", interval.String())
			continue
		}
		switch answer.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied":
			c.setStatus(handle, StatusDenied)
			return
		case "expired_token":
			c.setStatus(handle, StatusExpired)
			return
		case "":
			c.finish(handle, endpoints, answer)
			return
		default:
			slog.Warn("oidc token endpoint refused the device grant", "error", answer.Error)
			c.setStatus(handle, StatusFailed)
			return
		}
	}
}

func (c *client) finish(handle string, endpoints *providerEndpoints, answer *tokenAnswer) {
	jwks, err := c.provider.refreshJWKS(endpoints.JWKSURI)
	if err != nil {
		slog.Error("oidc jwks fetch failed", "error", err)
		c.setStatus(handle, StatusFailed)
		return
	}
	identityToken := answer.IDToken
	if identityToken == "" {
		identityToken = answer.AccessToken
	}
	claims, err := validateToken(identityToken, jwks, c.provider.issuer, c.clientID)
	if err != nil {
		slog.Error("oidc identity token rejected", "error", err)
		c.setStatus(handle, StatusFailed)
		return
	}
	if !c.binding.allowed(claims) {
		slog.Warn("oidc login refused — not the bound account and not in oidc.allowed_users",
			"subject", claims.Subject, "email", claims.Email)
		c.setStatus(handle, StatusDenied)
		return
	}

	credential, err := c.completeLogin(claims, answer)
	if err != nil {
		slog.Error("oidc login completion failed", "error", err)
		c.setStatus(handle, StatusFailed)
		return
	}
	c.approve(handle, credential)
	slog.Info("oidc device login succeeded", "entity_id", credential.EntityID, "name", credential.Name)
}

func (c *client) completeLogin(claims *identityClaims, answer *tokenAnswer) (*Credential, error) {
	name := claims.Email
	if name == "" {
		name = claims.stableID()
	}
	apiKey, err := keys.GenerateKeyString(c.keyLength)
	if err != nil {
		return nil, err
	}
	entity, err := c.keys.Create(apiKey, name,
		keyDescriptionPrefix+time.Now().Format(time.RFC3339), "admin", c.hashRounds)
	if err != nil {
		return nil, err
	}
	if removed, perr := c.keys.PruneByDescriptionPrefix(keyDescriptionPrefix, mintedKeysKept); perr != nil {
		slog.Warn("oidc key prune failed", "error", perr)
	} else if removed > 0 {
		slog.Info("stale oidc login keys pruned", "removed", removed)
	}
	c.binding.record(entity.ID, claims, func(id int64) bool {
		_, kerr := c.keys.Get(id)
		return kerr == nil
	})
	c.tokens.set(answer)
	return &Credential{
		EntityID: entity.ID,
		Name:     entity.Name,
		Role:     entity.Role,
	}, nil
}

func (c *client) startSilent(ctx context.Context) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	endpoints, err := c.provider.endpoints(probeCtx)
	if err != nil {
		return "", err
	}
	if endpoints.Authorization == "" {
		return "", errors.New("issuer discovery document carries no authorization_endpoint")
	}

	verifier, challenge, err := pkcePair()
	if err != nil {
		return "", err
	}
	state, err := randomHex()
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	for existing, entry := range c.silent {
		if time.Now().After(entry.expiresAt) {
			delete(c.silent, existing)
		}
	}
	c.silent[state] = &silentFlow{verifier: verifier, expiresAt: time.Now().Add(silentTTL)}
	c.mu.Unlock()

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.clientID},
		"redirect_uri":          {c.redirectURI},
		"scope":                 {c.scope},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"none"},
	}
	return endpoints.Authorization + "?" + query.Encode(), nil
}

func (c *client) exchangeSilent(ctx context.Context, state, code string) (*Credential, error) {
	c.mu.Lock()
	pending := c.silent[state]
	delete(c.silent, state)
	c.mu.Unlock()
	if pending == nil || time.Now().After(pending.expiresAt) {
		return nil, errors.New("unknown or expired state")
	}
	return c.redeemCode(ctx, code, c.redirectURI, pending.verifier)
}

func (c *client) redeemCode(ctx context.Context, code, redirectURI, verifier string) (*Credential, error) {
	endpoints, err := c.provider.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	answer, err := exchangeCode(ctx, endpoints, c.clientID, code, redirectURI, verifier)
	if err != nil {
		return nil, err
	}
	if answer.Error != "" {
		return nil, errors.New("code exchange refused: " + answer.Error)
	}
	if answer.AccessToken == "" {
		return nil, errors.New("code exchange answered no access token")
	}

	jwks, err := c.provider.jwks(false)
	if err != nil {
		return nil, err
	}
	identityToken := answer.IDToken
	if identityToken == "" {
		identityToken = answer.AccessToken
	}
	claims, err := validateToken(identityToken, jwks, c.provider.issuer, c.clientID)
	if errors.Is(err, errUnknownKey) {
		if jwks, err = c.provider.jwks(true); err == nil {
			claims, err = validateToken(identityToken, jwks, c.provider.issuer, c.clientID)
		}
	}
	if err != nil {
		return nil, err
	}
	if !c.binding.allowed(claims) {
		return nil, errNotAllowed
	}
	return c.completeLogin(claims, answer)
}
