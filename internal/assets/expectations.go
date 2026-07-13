package assets

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
)

// initial-registry.json is SHI's bundled hash-expectation registry, embedded
// VERBATIM — updates are a copy from
// Super.Human.Installer/Assets/config/initial-registry.json (Mark's rule:
// it is data; cp it, never transcribe it). Shape:
//
//	{ "<role>": { "installers"|"hotfixes"|"fixpacks": [
//	    {"fileName", "sha256", "version": {"fullVersion", ...}, ...} ] } }
//
// Every entry seeds an expectation row (exists:false — no binaries) that
// verifies the user's own files.
//
//go:embed initial-registry.json
var initialRegistryJSON []byte

// shiRegistryEntry is one file entry in SHI's registry format (extra fields
// like id/description are ignored).
type shiRegistryEntry struct {
	FileName string `json:"fileName"`
	SHA256   string `json:"sha256"`
	Version  struct {
		FullVersion string `json:"fullVersion"`
	} `json:"version"`
}

// kindByGroup maps SHI's plural group names to the cache kinds.
var kindByGroup = map[string]string{
	"installers": KindInstaller,
	"fixpacks":   KindFixpack,
	"hotfixes":   KindHotfix,
}

// SeedExpectations loads the bundled expectations into the registry —
// insert-if-absent, so user-observed reality is never overwritten (SHI's
// initializeWithDefaults semantics). Entries land in each kind's default
// storage location (the built-in cache), so the locations must be synced
// first. Malformed seed data is logged and skipped, never fatal.
func SeedExpectations(ctx context.Context, store *Store) error {
	var registry map[string]map[string][]shiRegistryEntry
	if err := json.Unmarshal(initialRegistryJSON, &registry); err != nil {
		alog().Error("bundled initial-registry.json is not SHI registry format — no expectations seeded",
			"error", err)
		return nil
	}

	locations := map[string]*Location{}
	for _, kind := range []string{KindInstaller, KindFixpack, KindHotfix} {
		if location, err := store.DefaultLocation(ctx, kind); err == nil {
			locations[kind] = location
		}
	}

	seeded := 0
	for role, groups := range registry {
		if !ValidRole(role) {
			alog().Warn("skipping unusable initial-registry role", "role", role)
			continue
		}
		for group, entries := range groups {
			kind, known := kindByGroup[group]
			if !known {
				alog().Warn("skipping unknown initial-registry group", "role", role, "group", group)
				continue
			}
			location := locations[kind]
			if location == nil {
				alog().Warn("no storage location for initial-registry kind", "kind", kind)
				continue
			}
			for _, entry := range entries {
				if !ValidFilename(entry.FileName) || entry.SHA256 == "" {
					alog().Warn("skipping unusable initial-registry entry",
						"role", role, "group", group, "filename", entry.FileName)
					continue
				}
				if err := store.SeedExpectation(ctx, location.ID, role, kind,
					entry.FileName, entry.SHA256, entry.Version.FullVersion); err != nil {
					return fmt.Errorf("seed expectation %s/%s/%s: %w",
						role, kind, entry.FileName, err)
				}
				seeded++
			}
		}
	}
	if seeded > 0 {
		alog().Info("hash expectations seeded from the bundled registry", "entries", seeded)
	}
	return nil
}
