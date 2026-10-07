package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Tray one-time tokens (architecture item 1, locked design): clicking the
// tray "Open" mints a single-use, short-lived token carried to the browser in
// the URL fragment; the SPA exchanges it for a session. Local presence — the
// physical tray click — is the credential. Tokens live only in this process's
// memory, so a restart invalidates them all. A grant may carry a PRE-MINTED
// key (the SSO callback's handoff): claiming it opens the session on that key
// instead of minting a fresh tray key.
const trayTokenTTL = 60 * time.Second

type trayGrant struct {
	expiry time.Time
	keyID  int64
}

// TrayTokens is the in-memory single-use token registry.
type TrayTokens struct {
	mu     sync.Mutex
	tokens map[string]trayGrant
}

// NewTrayTokens returns an empty registry.
func NewTrayTokens() *TrayTokens {
	return &TrayTokens{tokens: map[string]trayGrant{}}
}

// Mint creates a new single-use token valid for the TTL.
func (t *TrayTokens) Mint() (string, error) {
	return t.mint(0)
}

// MintForKey creates a single-use token whose claim answers the key with this
// id instead of minting a fresh tray key (the SSO handoff).
func (t *TrayTokens) MintForKey(keyID int64) (string, error) {
	return t.mint(keyID)
}

func (t *TrayTokens) mint(keyID int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for tok, grant := range t.tokens {
		if now.After(grant.expiry) {
			delete(t.tokens, tok)
		}
	}

	t.tokens[token] = trayGrant{expiry: now.Add(trayTokenTTL), keyID: keyID}
	return token, nil
}

// Claim consumes a token exactly once (removed regardless of expiry state):
// ok reports a known, unexpired token, and keyID carries the pre-minted key's
// id when the grant holds one (0 = the claimer mints its own).
func (t *TrayTokens) Claim(token string) (keyID int64, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	grant, ok := t.tokens[token]
	if !ok {
		return 0, false
	}
	delete(t.tokens, token)
	if time.Now().After(grant.expiry) {
		return 0, false
	}
	return grant.keyID, true
}
