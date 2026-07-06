package assets

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
)

// initial-registry.json is the bundled hash-expectation set (SHI's
// initial-registry model: filenames + SHA-256 hashes + versions, NO
// binaries) — rows seed with exists:false and verify user-supplied files.
// Ships empty until Mark populates the known HCL hashes; the HCL downloader
// also records the live catalog's authoritative hashes as expectations.
//
//go:embed initial-registry.json
var initialRegistryJSON []byte

// expectation is one bundled registry entry.
type expectation struct {
	Role     string `json:"role"`
	Kind     string `json:"kind"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Version  string `json:"version"`
}

// SeedExpectations loads the bundled expectations into the registry —
// insert-if-absent, so user-observed reality is never overwritten (SHI's
// initializeWithDefaults semantics).
func SeedExpectations(ctx context.Context, store *Store) error {
	var entries []expectation
	if err := json.Unmarshal(initialRegistryJSON, &entries); err != nil {
		return fmt.Errorf("parse bundled initial-registry.json: %w", err)
	}
	for _, entry := range entries {
		if !ValidRole(entry.Role) || !ValidKind(entry.Kind) || !ValidFilename(entry.Filename) {
			alog().Warn("skipping unusable initial-registry entry",
				"role", entry.Role, "kind", entry.Kind, "filename", entry.Filename)
			continue
		}
		if err := store.SeedExpectation(ctx, entry.Role, entry.Kind, entry.Filename,
			entry.SHA256, entry.Version); err != nil {
			return fmt.Errorf("seed expectation %s/%s/%s: %w",
				entry.Role, entry.Kind, entry.Filename, err)
		}
	}
	return nil
}
