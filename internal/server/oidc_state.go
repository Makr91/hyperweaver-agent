package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

type oidcKeyIdentity struct {
	Email      string `json:"email"`
	CustomerID string `json:"customer_id"`
}

type oidcStateFile struct {
	BoundSubject    string                    `json:"bound_subject"`
	BoundEmail      string                    `json:"bound_email"`
	BoundCustomerID string                    `json:"bound_customer_id"`
	MintedKeys      map[int64]oidcKeyIdentity `json:"minted_keys"`
}

func oidcLoadState(path string) (*oidcStateFile, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return &oidcStateFile{MintedKeys: map[int64]oidcKeyIdentity{}}, nil
	}
	if err != nil {
		return nil, err
	}
	state := &oidcStateFile{}
	if uerr := json.Unmarshal(raw, state); uerr != nil {
		return nil, uerr
	}
	if state.MintedKeys == nil {
		state.MintedKeys = map[int64]oidcKeyIdentity{}
	}
	return state, nil
}

func oidcSaveState(path string, state *oidcStateFile) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return safepath.WriteFile(path, raw, 0o600)
}

func (m *oidcManager) saveStateLocked() {
	state := &oidcStateFile{
		BoundSubject:    m.boundSubject,
		BoundEmail:      m.boundEmail,
		BoundCustomerID: m.boundCustomerID,
		MintedKeys:      m.mintedKeys,
	}
	if err := oidcSaveState(m.storePath, state); err != nil {
		slog.Error("oidc state save failed", "error", err)
	}
}

func (m *oidcManager) identityForKey(id int64) (oidcKeyIdentity, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	identity, ok := m.mintedKeys[id]
	return identity, ok
}
