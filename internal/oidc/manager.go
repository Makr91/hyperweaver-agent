// Package oidc is the agent's OpenID Connect client, resource-server validator and outbound token source against the configured issuer.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/dpop"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

// The states a device login flow passes through.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusFailed   = "failed"
)

const (
	keyDescriptionPrefix = "Created by OIDC device login "
	mintedKeysKept       = 5
	unknownKidCooldown   = 5 * time.Minute
)

// Credential is the local API key a completed login minted.
type Credential struct {
	APIKey   string
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

// Manager drives the device and silent logins, validates issuer tokens and holds the bound account's tokens.
type Manager struct {
	enabled      bool
	issuer       string
	clientID     string
	scope        string
	deviceScope  string
	allowedUsers []string
	storePath    string
	hashRounds   int
	keyLength    int
	keys         *keys.Store
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	redirectURI string

	mu               sync.Mutex
	flows            map[string]*flow
	silent           map[string]*silentFlow
	boundSubject     string
	boundEmail       string
	boundCustomerID  string
	mintedKeys       map[int64]KeyIdentity
	accessToken      string
	refreshToken     string
	tokenExpiry      time.Time
	refreshing       bool
	jwks             *jwksDocument
	jwksFetched      time.Time
	unknownKids      map[string]time.Time
	endpoints        *providerEndpoints
	endpointsFetched time.Time
	proofs           *dpop.Seen
	baseURL          string
}

// New builds the manager from the configuration and loads the bound account from oidc.json beside the configuration files.
func New(cfg *config.Config, keyStore *keys.Store) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		enabled:      cfg.OIDC.Enabled,
		issuer:       cfg.OIDC.Issuer,
		clientID:     cfg.OIDC.ClientID,
		scope:        strings.Join(cfg.OIDC.Scopes, " "),
		deviceScope:  deviceScopeOf(cfg.OIDC.Scopes),
		allowedUsers: cfg.OIDC.AllowedUsers,
		storePath:    filepath.Join(cfg.Dir(), "oidc.json"),
		hashRounds:   cfg.APIKeys.HashRounds,
		keyLength:    cfg.APIKeys.KeyLength,
		redirectURI:  strings.TrimRight(cfg.BaseURL(), "/") + "/api/auth/oidc/callback",
		keys:         keyStore,
		ctx:          ctx,
		cancel:       cancel,
		flows:        map[string]*flow{},
		silent:       map[string]*silentFlow{},
		mintedKeys:   map[int64]KeyIdentity{},
		unknownKids:  map[string]time.Time{},
		proofs:       dpop.NewSeen(),
		baseURL:      strings.TrimRight(cfg.BaseURL(), "/"),
	}
	if !m.enabled {
		return m
	}
	state, err := loadState(m.storePath)
	if err != nil {
		slog.Warn("oidc state unreadable — starting unbound", "path", m.storePath, "error", err)
		state = &stateFile{MintedKeys: map[int64]KeyIdentity{}}
	}
	m.boundSubject = state.BoundSubject
	m.boundEmail = state.BoundEmail
	m.boundCustomerID = state.BoundCustomerID
	m.mintedKeys = state.MintedKeys
	return m
}

func deviceScopeOf(scopes []string) string {
	kept := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != "openid" {
			kept = append(kept, scope)
		}
	}
	return strings.Join(kept, " ")
}

// Close stops the token refresh loop and every device poll.
func (m *Manager) Close() {
	m.cancel()
	m.wg.Wait()
}

// BearerToken answers the bound account's access token while it is valid, else the empty string.
func (m *Manager) BearerToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accessToken == "" || time.Now().After(m.tokenExpiry) {
		return ""
	}
	return m.accessToken
}

func (m *Manager) cachedEndpoints(ctx context.Context) (*providerEndpoints, error) {
	m.mu.Lock()
	endpoints := m.endpoints
	fresh := time.Since(m.endpointsFetched) < 15*time.Minute
	m.mu.Unlock()
	if endpoints != nil && fresh {
		return endpoints, nil
	}
	fetched, err := discover(ctx, m.issuer)
	if err != nil {
		if endpoints != nil {
			return endpoints, nil
		}
		return nil, err
	}
	m.mu.Lock()
	m.endpoints = fetched
	m.endpointsFetched = time.Now()
	m.mu.Unlock()
	return fetched, nil
}

func (m *Manager) cachedJWKS(force bool) (*jwksDocument, error) {
	m.mu.Lock()
	jwks := m.jwks
	fresh := time.Since(m.jwksFetched) < 15*time.Minute
	m.mu.Unlock()
	if jwks != nil && fresh && !force {
		return jwks, nil
	}
	endpoints, err := m.cachedEndpoints(m.ctx)
	if err != nil {
		return nil, err
	}
	fetched, err := fetchJWKS(m.ctx, endpoints.JWKSURI)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.jwks = fetched
	m.jwksFetched = time.Now()
	m.mu.Unlock()
	return fetched, nil
}

func (m *Manager) kidRefetchAllowed(kid string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for known, seen := range m.unknownKids {
		if now.Sub(seen) > unknownKidCooldown {
			delete(m.unknownKids, known)
		}
	}
	if _, cooling := m.unknownKids[kid]; cooling {
		return false
	}
	m.unknownKids[kid] = now
	return true
}

func tokenKid(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	header := struct {
		Kid string `json:"kid"`
	}{}
	if json.Unmarshal(raw, &header) != nil {
		return ""
	}
	return header.Kid
}

// AuthenticateToken validates an issuer token presented as Bearer or DPoP and answers the admin identity of the bound account.
func (m *Manager) AuthenticateToken(r *http.Request, scheme auth.Scheme, token string) (*auth.Identity, error) {
	if !m.enabled {
		return nil, errors.New("federated login is disabled")
	}
	jwks, err := m.cachedJWKS(false)
	if err != nil {
		slog.Warn("oidc token auth: jwks unavailable", "error", err)
		return nil, errors.New("the identity provider's keys are unavailable")
	}
	claims, err := validateToken(token, jwks, m.issuer, m.clientID)
	if errors.Is(err, errUnknownKey) && m.kidRefetchAllowed(tokenKid(token)) {
		if jwks, err = m.cachedJWKS(true); err == nil {
			claims, err = validateToken(token, jwks, m.issuer, m.clientID)
		}
	}
	if err != nil {
		logging.Category("auth").Warn("oidc token rejected", "error", err)
		return nil, errors.New("invalid token")
	}
	switch {
	case scheme == auth.SchemeBearer && claims.BoundJKT != "":
		logging.Category("auth").Warn("key-bound token presented as Bearer")
		return nil, errors.New("a key-bound token must be presented with the DPoP scheme")
	case scheme == auth.SchemeDPoP && claims.BoundJKT == "":
		return nil, errors.New("the token is not key-bound")
	case scheme == auth.SchemeDPoP:
		proofs := r.Header.Values("DPoP")
		if len(proofs) != 1 {
			return nil, errors.New("exactly one DPoP proof header is required")
		}
		htu := m.baseURL + r.URL.Path
		if perr := dpop.Verify(proofs[0], r.Method, htu, token, claims.BoundJKT, time.Now(), m.proofs); perr != nil {
			logging.Category("auth").Warn("dpop proof rejected", "error", perr)
			return nil, errors.New("the DPoP proof was refused: " + perr.Error())
		}
	}
	if !m.subjectAllowed(claims) {
		logging.Category("auth").Warn("oidc token refused — not the bound account and not in oidc.allowed_users",
			"subject", claims.Subject, "email", claims.Email)
		return nil, errors.New("the account is not bound to this agent")
	}
	name := claims.Email
	if name == "" {
		name = claims.Subject
	}
	return &auth.Identity{Name: name, Description: "OIDC " + string(scheme) + " token", Role: "admin"}, nil
}

// Start begins a device login at the issuer and answers the agent-side handle and the issuer's authorization.
func (m *Manager) Start(ctx context.Context) (string, *DeviceAuthorization, error) {
	endpoints, err := discover(ctx, m.issuer)
	if err != nil {
		return "", nil, err
	}
	authorization, err := startDeviceAuthorization(ctx, endpoints, m.clientID, m.deviceScope)
	if err != nil {
		return "", nil, err
	}
	raw := make([]byte, 32)
	if _, rerr := rand.Read(raw); rerr != nil {
		return "", nil, rerr
	}
	handle := hex.EncodeToString(raw)
	expiresAt := time.Now().Add(time.Duration(authorization.ExpiresIn) * time.Second)

	m.mu.Lock()
	for existing, entry := range m.flows {
		if time.Now().After(entry.expiresAt.Add(10 * time.Minute)) {
			delete(m.flows, existing)
		}
	}
	m.flows[handle] = &flow{
		status:    StatusPending,
		expiresAt: expiresAt,
		interval:  time.Duration(authorization.Interval) * time.Second,
		changed:   make(chan struct{}),
	}
	m.mu.Unlock()

	m.wg.Add(1)
	go m.watch(handle, endpoints, authorization, expiresAt)

	return handle, authorization, nil
}

// Await blocks while the flow is pending, until it changes, the grant's interval elapses or the request ends.
func (m *Manager) Await(ctx context.Context, handle string) {
	m.mu.Lock()
	entry := m.flows[handle]
	if entry == nil || entry.status != StatusPending {
		m.mu.Unlock()
		return
	}
	changed := entry.changed
	interval := entry.interval
	m.mu.Unlock()
	select {
	case <-changed:
	case <-ctx.Done():
	case <-time.After(interval):
	}
}

// Status answers a flow's state; an approved flow hands over its credential once and is then forgotten, as is an expired one.
func (m *Manager) Status(handle string) (string, *Credential, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.flows[handle]
	if entry == nil {
		return "", nil, false
	}
	switch entry.status {
	case StatusApproved:
		credential := entry.credential
		delete(m.flows, handle)
		return StatusApproved, credential, true
	case StatusExpired:
		delete(m.flows, handle)
		return StatusExpired, nil, true
	default:
		return entry.status, nil, true
	}
}

func (m *Manager) setStatus(handle, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.flows[handle]; entry != nil && entry.status == StatusPending {
		entry.status = status
		close(entry.changed)
	}
}

func (m *Manager) watch(handle string, endpoints *providerEndpoints, authorization *DeviceAuthorization, deadline time.Time) {
	defer m.wg.Done()
	interval := time.Duration(authorization.Interval) * time.Second
	for {
		wait := interval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(wait):
		}
		if time.Now().After(deadline) {
			m.setStatus(handle, StatusExpired)
			return
		}
		answer, err := pollToken(m.ctx, endpoints, m.clientID, authorization.DeviceCode)
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
			m.setStatus(handle, StatusDenied)
			return
		case "expired_token":
			m.setStatus(handle, StatusExpired)
			return
		case "":
			m.finish(handle, endpoints, answer)
			return
		default:
			slog.Warn("oidc token endpoint refused the device grant", "error", answer.Error)
			m.setStatus(handle, StatusFailed)
			return
		}
	}
}

func (m *Manager) finish(handle string, endpoints *providerEndpoints, answer *tokenAnswer) {
	jwks, err := fetchJWKS(m.ctx, endpoints.JWKSURI)
	if err != nil {
		slog.Error("oidc jwks fetch failed", "error", err)
		m.setStatus(handle, StatusFailed)
		return
	}
	m.mu.Lock()
	m.jwks = jwks
	m.jwksFetched = time.Now()
	m.mu.Unlock()
	identityToken := answer.IDToken
	if identityToken == "" {
		identityToken = answer.AccessToken
	}
	claims, err := validateToken(identityToken, jwks, m.issuer, m.clientID)
	if err != nil {
		slog.Error("oidc identity token rejected", "error", err)
		m.setStatus(handle, StatusFailed)
		return
	}
	if !m.subjectAllowed(claims) {
		slog.Warn("oidc login refused — not the bound account and not in oidc.allowed_users",
			"subject", claims.Subject, "email", claims.Email)
		m.setStatus(handle, StatusDenied)
		return
	}

	credential, err := m.completeLogin(claims, answer)
	if err != nil {
		slog.Error("oidc login completion failed", "error", err)
		m.setStatus(handle, StatusFailed)
		return
	}
	m.mu.Lock()
	if entry := m.flows[handle]; entry != nil && entry.status == StatusPending {
		entry.status = StatusApproved
		entry.credential = credential
		close(entry.changed)
	}
	m.mu.Unlock()
	slog.Info("oidc device login succeeded", "entity_id", credential.EntityID, "name", credential.Name)
}

func (m *Manager) completeLogin(claims *identityClaims, answer *tokenAnswer) (*Credential, error) {
	name := claims.Email
	if name == "" {
		name = claims.stableID()
	}
	apiKey, err := keys.GenerateKeyString(m.keyLength)
	if err != nil {
		return nil, err
	}
	entity, err := m.keys.Create(apiKey, name,
		keyDescriptionPrefix+time.Now().Format(time.RFC3339), "admin", m.hashRounds)
	if err != nil {
		return nil, err
	}
	if removed, perr := m.keys.PruneByDescriptionPrefix(keyDescriptionPrefix, mintedKeysKept); perr != nil {
		slog.Warn("oidc key prune failed", "error", perr)
	} else if removed > 0 {
		slog.Info("stale oidc login keys pruned", "removed", removed)
	}

	m.mu.Lock()
	if m.boundSubject == "" {
		m.boundSubject = claims.stableID()
		m.boundEmail = claims.Email
		m.boundCustomerID = claims.CustomerID
		slog.Info("oidc login bound this agent to its first account",
			"id", claims.stableID(), "email", claims.Email)
	} else if claims.stableID() == m.boundSubject {
		m.boundEmail = claims.Email
		m.boundCustomerID = claims.CustomerID
	}
	m.mintedKeys[entity.ID] = KeyIdentity{Email: claims.Email, CustomerID: claims.CustomerID}
	for id := range m.mintedKeys {
		if id == entity.ID {
			continue
		}
		if _, kerr := m.keys.Get(id); kerr != nil {
			delete(m.mintedKeys, id)
		}
	}
	m.accessToken = answer.AccessToken
	if answer.RefreshToken != "" {
		m.refreshToken = answer.RefreshToken
	}
	m.tokenExpiry = time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	m.saveStateLocked()
	m.mu.Unlock()
	m.startRefreshLoop()
	return &Credential{
		APIKey:   apiKey,
		EntityID: entity.ID,
		Name:     entity.Name,
		Role:     entity.Role,
	}, nil
}

func (m *Manager) subjectAllowed(claims *identityClaims) bool {
	m.mu.Lock()
	bound := m.boundSubject
	m.mu.Unlock()
	if bound == "" || claims.stableID() == bound {
		return true
	}
	for _, allowed := range m.allowedUsers {
		if allowed == claims.UUID || allowed == claims.Subject ||
			(claims.Email != "" && strings.EqualFold(allowed, claims.Email)) {
			return true
		}
	}
	return false
}
