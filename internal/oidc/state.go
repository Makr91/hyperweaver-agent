package oidc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

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

func saveState(path string, state *stateFile) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return safepath.WriteFile(path, raw, 0o600)
}

func (m *Manager) saveStateLocked() {
	state := &stateFile{
		BoundSubject:    m.boundSubject,
		BoundEmail:      m.boundEmail,
		BoundCustomerID: m.boundCustomerID,
		MintedKeys:      m.mintedKeys,
	}
	if err := saveState(m.storePath, state); err != nil {
		slog.Error("oidc state save failed", "error", err)
	}
}

// IdentityForKey answers the federated account a key was minted for, false for a plain key.
func (m *Manager) IdentityForKey(id int64) (KeyIdentity, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	identity, ok := m.mintedKeys[id]
	return identity, ok
}
