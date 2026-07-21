package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

const (
	oidcStatusPending  = "pending"
	oidcStatusApproved = "approved"
	oidcStatusDenied   = "denied"
	oidcStatusExpired  = "expired"

	oidcKeyDescriptionPrefix = "Created by OIDC device login "
	oidcMintedKeysKept       = 5
)

type oidcCredential struct {
	apiKey   string
	entityID int64
	name     string
	role     string
	message  string
}

type oidcFlow struct {
	status     string
	credential *oidcCredential
	expiresAt  time.Time
}

type oidcBindingFile struct {
	BoundSubject string `json:"bound_subject"`
	BoundEmail   string `json:"bound_email"`
}

type oidcManager struct {
	enabled      bool
	issuer       string
	clientID     string
	scope        string
	allowedUsers []string
	storePath    string
	hashRounds   int
	keyLength    int
	keys         *keys.Store
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	mu           sync.Mutex
	flows        map[string]*oidcFlow
	boundSubject string
	boundEmail   string
	accessToken  string
	refreshToken string
	tokenExpiry  time.Time
	refreshing   bool
	jwks         *oidcJWKSDocument
	jwksFetched  time.Time
}

func newOIDCManager(cfg *config.Config, keyStore *keys.Store) *oidcManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &oidcManager{
		enabled:      cfg.OIDC.Enabled,
		issuer:       cfg.OIDC.Issuer,
		clientID:     cfg.OIDC.ClientID,
		scope:        strings.Join(cfg.OIDC.Scopes, " "),
		allowedUsers: cfg.OIDC.AllowedUsers,
		storePath:    filepath.Join(filepath.Dir(cfg.Path()), "oidc.json"),
		hashRounds:   cfg.APIKeys.HashRounds,
		keyLength:    cfg.APIKeys.KeyLength,
		keys:         keyStore,
		ctx:          ctx,
		cancel:       cancel,
		flows:        map[string]*oidcFlow{},
	}
	if !m.enabled {
		return m
	}
	binding, err := oidcLoadBinding(m.storePath)
	if err != nil {
		slog.Warn("oidc binding unreadable — starting unbound", "path", m.storePath, "error", err)
		binding = &oidcBindingFile{}
	}
	m.boundSubject = binding.BoundSubject
	m.boundEmail = binding.BoundEmail
	return m
}

func oidcLoadBinding(path string) (*oidcBindingFile, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return &oidcBindingFile{}, nil
	}
	if err != nil {
		return nil, err
	}
	binding := &oidcBindingFile{}
	if uerr := json.Unmarshal(raw, binding); uerr != nil {
		return nil, uerr
	}
	return binding, nil
}

func oidcSaveBinding(path string, binding *oidcBindingFile) error {
	raw, err := json.MarshalIndent(binding, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return safepath.WriteFile(path, raw, 0o600)
}

func (m *oidcManager) close() {
	m.cancel()
	m.wg.Wait()
}

func (m *oidcManager) bearerToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.accessToken == "" || time.Now().After(m.tokenExpiry) {
		return ""
	}
	return m.accessToken
}

func (m *oidcManager) cachedJWKS(force bool) (*oidcJWKSDocument, error) {
	m.mu.Lock()
	jwks := m.jwks
	fresh := time.Since(m.jwksFetched) < 15*time.Minute
	m.mu.Unlock()
	if jwks != nil && fresh && !force {
		return jwks, nil
	}
	endpoints, err := oidcDiscover(m.ctx, m.issuer)
	if err != nil {
		return nil, err
	}
	fetched, err := oidcFetchJWKS(m.ctx, endpoints.JWKSURI)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.jwks = fetched
	m.jwksFetched = time.Now()
	m.mu.Unlock()
	return fetched, nil
}

func (m *oidcManager) authenticateBearer(token string) *auth.Identity {
	if !m.enabled {
		return nil
	}
	jwks, err := m.cachedJWKS(false)
	if err != nil {
		slog.Warn("oidc bearer auth: jwks unavailable", "error", err)
		return nil
	}
	claims, err := oidcValidateToken(token, jwks, m.issuer, m.clientID)
	if errors.Is(err, errOIDCUnknownKey) {
		if jwks, err = m.cachedJWKS(true); err == nil {
			claims, err = oidcValidateToken(token, jwks, m.issuer, m.clientID)
		}
	}
	if err != nil {
		logging.Category("auth").Warn("oidc bearer token rejected", "error", err)
		return nil
	}
	if !m.subjectAllowed(claims) {
		logging.Category("auth").Warn("oidc bearer refused — not the bound account and not in oidc.allowed_users",
			"subject", claims.Subject, "email", claims.Email)
		return nil
	}
	name := claims.Email
	if name == "" {
		name = claims.Subject
	}
	return &auth.Identity{Name: name, Description: "OIDC bearer token", Role: "admin"}
}

func (m *oidcManager) start(ctx context.Context) (*deviceStartResponse, error) {
	endpoints, err := oidcDiscover(ctx, m.issuer)
	if err != nil {
		return nil, err
	}
	authorization, err := oidcStartDeviceAuthorization(ctx, endpoints, m.clientID, m.scope)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 32)
	if _, rerr := rand.Read(raw); rerr != nil {
		return nil, rerr
	}
	handle := hex.EncodeToString(raw)
	expiresAt := time.Now().Add(time.Duration(authorization.ExpiresIn) * time.Second)

	m.mu.Lock()
	for existing, entry := range m.flows {
		if time.Now().After(entry.expiresAt.Add(10 * time.Minute)) {
			delete(m.flows, existing)
		}
	}
	m.flows[handle] = &oidcFlow{status: oidcStatusPending, expiresAt: expiresAt}
	m.mu.Unlock()

	m.wg.Add(1)
	go m.watch(handle, endpoints, authorization, expiresAt)

	return &deviceStartResponse{
		Handle:                  handle,
		UserCode:                authorization.UserCode,
		VerificationURI:         authorization.VerificationURI,
		VerificationURIComplete: authorization.VerificationURIComplete,
		ExpiresIn:               authorization.ExpiresIn,
		Interval:                authorization.Interval,
	}, nil
}

func (m *oidcManager) status(handle string) (string, *oidcCredential, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.flows[handle]
	if entry == nil {
		return "", nil, false
	}
	switch entry.status {
	case oidcStatusApproved:
		credential := entry.credential
		delete(m.flows, handle)
		return oidcStatusApproved, credential, true
	case oidcStatusExpired:
		delete(m.flows, handle)
		return oidcStatusExpired, nil, true
	default:
		return entry.status, nil, true
	}
}

func (m *oidcManager) setStatus(handle, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.flows[handle]; entry != nil {
		entry.status = status
	}
}

func (m *oidcManager) watch(handle string, endpoints *oidcProviderEndpoints, authorization *oidcDeviceAuthorization, deadline time.Time) {
	defer m.wg.Done()
	interval := time.Duration(authorization.Interval) * time.Second
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			m.setStatus(handle, oidcStatusExpired)
			return
		}
		answer, err := oidcPollToken(m.ctx, endpoints, m.clientID, authorization.DeviceCode)
		if err != nil {
			slog.Warn("oidc token poll failed — retrying", "error", err)
			continue
		}
		switch answer.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied":
			m.setStatus(handle, oidcStatusDenied)
			return
		case "expired_token":
			m.setStatus(handle, oidcStatusExpired)
			return
		case "":
			m.finish(handle, endpoints, answer)
			return
		default:
			slog.Warn("oidc token endpoint refused the device grant", "error", answer.Error)
			m.setStatus(handle, oidcStatusDenied)
			return
		}
	}
}

func (m *oidcManager) finish(handle string, endpoints *oidcProviderEndpoints, answer *oidcTokenAnswer) {
	jwks, err := oidcFetchJWKS(m.ctx, endpoints.JWKSURI)
	if err != nil {
		slog.Error("oidc jwks fetch failed", "error", err)
		m.setStatus(handle, oidcStatusDenied)
		return
	}
	m.mu.Lock()
	m.jwks = jwks
	m.jwksFetched = time.Now()
	m.mu.Unlock()
	claims, err := oidcValidateToken(answer.IDToken, jwks, m.issuer, m.clientID)
	if err != nil {
		slog.Error("oidc id_token rejected", "error", err)
		m.setStatus(handle, oidcStatusDenied)
		return
	}
	if !m.subjectAllowed(claims) {
		slog.Warn("oidc login refused — not the bound account and not in oidc.allowed_users",
			"subject", claims.Subject, "email", claims.Email)
		m.setStatus(handle, oidcStatusDenied)
		return
	}

	name := claims.Email
	if name == "" {
		name = claims.Subject
	}
	apiKey, err := keys.GenerateKeyString(m.keyLength)
	if err != nil {
		slog.Error("oidc key generation failed", "error", err)
		m.setStatus(handle, oidcStatusDenied)
		return
	}
	entity, err := m.keys.Create(apiKey, name,
		oidcKeyDescriptionPrefix+time.Now().Format(time.RFC3339), "admin", m.hashRounds)
	if err != nil {
		slog.Error("oidc key creation failed", "error", err)
		m.setStatus(handle, oidcStatusDenied)
		return
	}
	if removed, perr := m.keys.PruneByDescriptionPrefix(oidcKeyDescriptionPrefix, oidcMintedKeysKept); perr != nil {
		slog.Warn("oidc key prune failed", "error", perr)
	} else if removed > 0 {
		slog.Info("stale oidc login keys pruned", "removed", removed)
	}

	m.mu.Lock()
	if m.boundSubject == "" {
		m.boundSubject = claims.Subject
		m.boundEmail = claims.Email
		if serr := oidcSaveBinding(m.storePath, &oidcBindingFile{
			BoundSubject: m.boundSubject,
			BoundEmail:   m.boundEmail,
		}); serr != nil {
			slog.Error("oidc binding save failed", "error", serr)
		}
		slog.Info("oidc login bound this agent to its first account",
			"subject", claims.Subject, "email", claims.Email)
	}
	m.accessToken = answer.AccessToken
	if answer.RefreshToken != "" {
		m.refreshToken = answer.RefreshToken
	}
	m.tokenExpiry = time.Now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	if entry := m.flows[handle]; entry != nil {
		entry.status = oidcStatusApproved
		entry.credential = &oidcCredential{
			apiKey:   apiKey,
			entityID: entity.ID,
			name:     entity.Name,
			role:     entity.Role,
			message:  "OIDC device login successful",
		}
	}
	m.mu.Unlock()
	m.startRefreshLoop()
	slog.Info("oidc device login succeeded", "entity_id", entity.ID, "name", entity.Name)
}

func (m *oidcManager) subjectAllowed(claims *oidcIdentityClaims) bool {
	m.mu.Lock()
	bound := m.boundSubject
	m.mu.Unlock()
	if bound == "" || claims.Subject == bound {
		return true
	}
	for _, allowed := range m.allowedUsers {
		if allowed == claims.Subject || (claims.Email != "" && strings.EqualFold(allowed, claims.Email)) {
			return true
		}
	}
	return false
}

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
