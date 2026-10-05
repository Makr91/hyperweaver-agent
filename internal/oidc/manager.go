// Package oidc is the agent's OpenID Connect client, resource-server validator and outbound token source against the configured issuer.
package oidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/dpop"
	"github.com/Makr91/hyperweaver-agent/internal/keys"
)

// The states a device login flow passes through.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
	StatusFailed   = "failed"
)

// Manager composes the issuer cache, the bound account, the token validator, the outbound token source and the login client.
type Manager struct {
	enabled   bool
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	provider  *provider
	binding   *binding
	validator *validator
	tokens    *tokenSource
	client    *client
}

// New builds the manager from the configuration and loads the bound account from oidc.json beside the configuration files.
func New(cfg *config.Config, keyStore *keys.Store) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{enabled: cfg.OIDC.Enabled, cancel: cancel}
	baseURL := strings.TrimRight(cfg.BaseURL(), "/")
	m.provider = &provider{issuer: cfg.OIDC.Issuer, ctx: ctx, unknownKids: map[string]time.Time{}}
	m.binding = newBinding(filepath.Join(cfg.Dir(), "oidc.json"), cfg.OIDC.AllowedUsers, m.enabled)
	m.validator = &validator{
		provider: m.provider,
		binding:  m.binding,
		clientID: cfg.OIDC.ClientID,
		baseURL:  baseURL,
		proofs:   dpop.NewSeen(),
	}
	m.tokens = &tokenSource{provider: m.provider, clientID: cfg.OIDC.ClientID, ctx: ctx, wg: &m.wg, persist: m.binding.setRefreshToken}
	m.client = &client{
		provider:    m.provider,
		binding:     m.binding,
		tokens:      m.tokens,
		keys:        keyStore,
		ctx:         ctx,
		wg:          &m.wg,
		clientID:    cfg.OIDC.ClientID,
		scope:       strings.Join(cfg.OIDC.Scopes, " "),
		deviceScope: deviceScopeOf(cfg.OIDC.Scopes),
		redirectURI: baseURL + "/api/auth/oidc/callback",
		hashRounds:  cfg.APIKeys.HashRounds,
		keyLength:   cfg.APIKeys.KeyLength,
		flows:       map[string]*flow{},
		silent:      map[string]*silentFlow{},
		codeFlows:   map[string]*codeFlow{},
	}
	if m.enabled {
		m.tokens.resume(m.binding.storedRefreshToken())
	}
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
	return m.tokens.bearer()
}

// Issuer answers the configured identity provider's origin.
func (m *Manager) Issuer() string {
	return m.provider.issuer
}

// ErrNoToken is answered when no valid token for the bound account is held.
var ErrNoToken = errors.New("no valid token for the bound account is held")

// IssuerRequest sends one request to the issuer under the bound account's Bearer token; the caller closes the body.
func (m *Manager) IssuerRequest(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	token := m.tokens.bearer()
	if token == "" {
		return nil, ErrNoToken
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(m.provider.issuer, "/")+path, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	return httpClient.Do(request)
}

// AuthenticateToken validates an issuer token presented as Bearer or DPoP and answers the admin identity of the bound account.
func (m *Manager) AuthenticateToken(r *http.Request, scheme auth.Scheme, token string) (*auth.Identity, error) {
	if !m.enabled {
		return nil, errors.New("federated login is disabled")
	}
	return m.validator.authenticate(r, scheme, token)
}

// BoundSubject answers the stable id of the account the agent is bound to, empty while unbound.
func (m *Manager) BoundSubject() string {
	m.binding.mu.Lock()
	defer m.binding.mu.Unlock()
	return m.binding.subject
}

// IdentityForKey answers the federated account a key was minted for, false for a plain key.
func (m *Manager) IdentityForKey(id int64) (KeyIdentity, bool) {
	return m.binding.identityForKey(id)
}

// Start begins a device login at the issuer and answers the agent-side handle and the issuer's authorization.
func (m *Manager) Start(ctx context.Context) (string, *DeviceAuthorization, error) {
	return m.client.start(ctx)
}

// Await blocks while the flow is pending, until it changes, the grant's interval elapses or the request ends.
func (m *Manager) Await(ctx context.Context, handle string) {
	m.client.await(ctx, handle)
}

// Status answers a flow's state; an approved flow hands over its credential once and is then forgotten, as is an expired one.
func (m *Manager) Status(handle string) (string, *Credential, bool) {
	return m.client.status(handle)
}

// StartSilent mints a state and PKCE verifier and answers the issuer's prompt=none authorize URL.
func (m *Manager) StartSilent(ctx context.Context) (string, error) {
	return m.client.startSilent(ctx)
}

// ExchangeSilent trades the callback's code for tokens with the held verifier and completes the login.
func (m *Manager) ExchangeSilent(ctx context.Context, state, code string) (*Credential, error) {
	return m.client.exchangeSilent(ctx, state, code)
}

// StartCode mints a state, PKCE verifier and handle for an interactive code login and answers the handle, the authorize URL, the manual URL whose redirect_uri is the issuer's code page, and the seconds until it expires.
func (m *Manager) StartCode(ctx context.Context, loopback bool) (handle, authorizeURL, manualURL string, expiresIn int, err error) {
	return m.client.startCode(ctx, loopback)
}

// CodeFlowHandle answers the handle of the code login a callback state belongs to, false for any other state.
func (m *Manager) CodeFlowHandle(state string) (string, bool) {
	return m.client.codeFlowHandle(state)
}

// RefuseCode forgets a code login's state and settles its handle as denied or failed.
func (m *Manager) RefuseCode(state, status string) {
	m.client.refuseCode(state, status)
}

// ExchangeCode trades the callback's code for tokens with the flow's verifier, completes the login and settles its handle.
func (m *Manager) ExchangeCode(ctx context.Context, state, code string) (*Credential, error) {
	return m.client.exchangeCodeFlow(ctx, state, code)
}

// SubmitCode redeems a pasted code against a pending handle, state being the pasted one or empty, and answers the settled status.
func (m *Manager) SubmitCode(ctx context.Context, handle, code, state string) (string, error) {
	return m.client.submitCode(ctx, handle, code, state)
}
