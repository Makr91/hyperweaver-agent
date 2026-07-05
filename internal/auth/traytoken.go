package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Tray one-time tokens (architecture item 1, locked design): clicking the
// tray "Open" mints a single-use, short-lived token carried to the browser in
// the URL fragment; the SPA exchanges it for an API key. Local presence — the
// physical tray click — is the credential. Tokens live only in this process's
// memory, so a restart invalidates them all.
const trayTokenTTL = 60 * time.Second

// TrayTokens is the in-memory single-use token registry.
type TrayTokens struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

// NewTrayTokens returns an empty registry.
func NewTrayTokens() *TrayTokens {
	return &TrayTokens{tokens: map[string]time.Time{}}
}

// Mint creates a new single-use token valid for the TTL.
func (t *TrayTokens) Mint() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	t.mu.Lock()
	defer t.mu.Unlock()

	// Opportunistic prune so abandoned mints don't accumulate.
	now := time.Now()
	for tok, expiry := range t.tokens {
		if now.After(expiry) {
			delete(t.tokens, tok)
		}
	}

	t.tokens[token] = now.Add(trayTokenTTL)
	return token, nil
}

// Claim consumes a token: true only for a known, unexpired token, exactly
// once — the token is removed regardless of expiry state.
func (t *TrayTokens) Claim(token string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	expiry, ok := t.tokens[token]
	if !ok {
		return false
	}
	delete(t.tokens, token)
	return time.Now().Before(expiry)
}
