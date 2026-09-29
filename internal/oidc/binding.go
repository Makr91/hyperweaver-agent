package oidc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// KeyIdentity is the federated account a minted key stands for.
type KeyIdentity struct {
	Email      string `json:"email"`
	CustomerID string `json:"customer_id"`
}

type stateFile struct {
	BoundSubject    string                `json:"bound_subject"`
	BoundEmail      string                `json:"bound_email"`
	BoundCustomerID string                `json:"bound_customer_id"`
	MintedKeys      map[int64]KeyIdentity `json:"minted_keys"`
}

type binding struct {
	mu           sync.Mutex
	storePath    string
	allowedUsers []string
	subject      string
	email        string
	customerID   string
	mintedKeys   map[int64]KeyIdentity
}

func newBinding(storePath string, allowedUsers []string, load bool) *binding {
	b := &binding{storePath: storePath, allowedUsers: allowedUsers, mintedKeys: map[int64]KeyIdentity{}}
	if !load {
		return b
	}
	state, err := loadState(storePath)
	if err != nil {
		slog.Warn("oidc state unreadable — starting unbound", "path", storePath, "error", err)
		return b
	}
	b.subject = state.BoundSubject
	b.email = state.BoundEmail
	b.customerID = state.BoundCustomerID
	b.mintedKeys = state.MintedKeys
	return b
}

func loadState(path string) (*stateFile, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return &stateFile{MintedKeys: map[int64]KeyIdentity{}}, nil
	}
	if err != nil {
		return nil, err
	}
	state := &stateFile{}
	if uerr := json.Unmarshal(raw, state); uerr != nil {
		return nil, uerr
	}
	if state.MintedKeys == nil {
		state.MintedKeys = map[int64]KeyIdentity{}
	}
	return state, nil
}

func (b *binding) saveLocked() {
	state := &stateFile{
		BoundSubject:    b.subject,
		BoundEmail:      b.email,
		BoundCustomerID: b.customerID,
		MintedKeys:      b.mintedKeys,
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		slog.Error("oidc state save failed", "error", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(b.storePath), 0o700); err != nil {
		slog.Error("oidc state save failed", "error", err)
		return
	}
	if err := safepath.WriteFile(b.storePath, raw, 0o600); err != nil {
		slog.Error("oidc state save failed", "error", err)
	}
}

func (b *binding) allowed(claims *identityClaims) bool {
	b.mu.Lock()
	bound := b.subject
	b.mu.Unlock()
	if bound == "" || claims.stableID() == bound {
		return true
	}
	for _, allowed := range b.allowedUsers {
		if allowed == claims.UUID || allowed == claims.Subject ||
			(claims.Email != "" && strings.EqualFold(allowed, claims.Email)) {
			return true
		}
	}
	return false
}

func (b *binding) record(entityID int64, claims *identityClaims, keyExists func(int64) bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subject == "" {
		b.subject = claims.stableID()
		b.email = claims.Email
		b.customerID = claims.CustomerID
		slog.Info("oidc login bound this agent to its first account",
			"id", claims.stableID(), "email", claims.Email)
	} else if claims.stableID() == b.subject {
		b.email = claims.Email
		b.customerID = claims.CustomerID
	}
	b.mintedKeys[entityID] = KeyIdentity{Email: claims.Email, CustomerID: claims.CustomerID}
	for id := range b.mintedKeys {
		if id != entityID && !keyExists(id) {
			delete(b.mintedKeys, id)
		}
	}
	b.saveLocked()
}

func (b *binding) identityForKey(id int64) (KeyIdentity, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	identity, ok := b.mintedKeys[id]
	return identity, ok
}
