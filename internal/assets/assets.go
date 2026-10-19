// Package assets implements the merged artifact system (Mark's ruling
// 2026-07-09: ONE system, zoneweaver-shaped): typed storage locations where
// iso, image, installer, fixpack, and hotfix are all location types — one
// scan, one checksum store, one wire surface. SHI's hash-expectation model
// (seeded expectations, verify-then-mount) rides on top: a file that is
// absent, unhashed, or failing verification never reaches a machine.
package assets

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// alog is this package's category logger (logging.categories.assets).
func alog() *slog.Logger {
	return logging.Category("assets")
}

const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// newLocationID mints a random UUIDv4 (zoneweaver's location id format).
func newLocationID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	s := hex.EncodeToString(raw)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32], nil
}

// Store persists locations and artifacts in agent.sqlite; root is the
// built-in locations' parent directory; registry is the files the box registries list, rebuilt by every sync.
type Store struct {
	db       *sql.DB
	root     string
	registry atomic.Pointer[RegistryIndex]
}

// NewStore wraps the opened agent database over the artifact root.
func NewStore(database *sql.DB, root string) *Store {
	store := &Store{db: database, root: root}
	store.registry.Store(newRegistryIndex())
	return store
}

// RegistryIndex answers the files the box registries listed at the last sync.
func (s *Store) RegistryIndex() *RegistryIndex {
	return s.registry.Load()
}

// SetRegistryIndex replaces the registry index whole.
func (s *Store) SetRegistryIndex(index *RegistryIndex) {
	s.registry.Store(index)
}

// MergeRegistryIndex adds one registry's files to the index, replacing the files it listed before.
func (s *Store) MergeRegistryIndex(index *RegistryIndex) {
	merged := newRegistryIndex()
	sources := map[string]bool{}
	index.mu.RLock()
	for sha := range index.bySHA {
		sources[index.bySHA[sha].SourceName] = true
	}
	for _, refs := range index.byName {
		for i := range refs {
			sources[refs[i].SourceName] = true
		}
	}
	index.mu.RUnlock()
	current := s.registry.Load()
	current.mu.RLock()
	for _, refs := range current.byName {
		for i := range refs {
			if !sources[refs[i].SourceName] {
				merged.add(&refs[i])
			}
		}
	}
	current.mu.RUnlock()
	index.mu.RLock()
	for _, refs := range index.byName {
		for i := range refs {
			merged.add(&refs[i])
		}
	}
	index.mu.RUnlock()
	s.registry.Store(merged)
}

// Root returns the artifact root (the built-in locations' parent).
func (s *Store) Root() string {
	return s.root
}

// PathFor computes (and containment-checks) a file's location inside a
// storage location: <path>/<role>/<file> for role-keyed types,
// <path>/<file> flat for iso/image.
func PathFor(location *Location, role, filename string) (string, error) {
	if !ValidFilename(filename) {
		return "", fmt.Errorf("filename %q is not usable", filename)
	}
	if RoleKeyed(location.Type) {
		if !ValidRole(role) {
			return "", fmt.Errorf("role %q is not usable (required for %s locations)", role, location.Type)
		}
		return safepath.Under(location.Path, filepath.Join(role, filename))
	}
	return safepath.Under(location.Path, filename)
}

// HashFile computes a file's SHA-256, the one key every artifact is known by.
func HashFile(path string) (sha string, size int64, err error) {
	hasher := sha256.New()
	n, err := copyFileTo(path, hasher)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}

func copyFileTo(path string, w io.Writer) (int64, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = f.Close()
	}()
	return io.Copy(w, f)
}
