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
// built-in locations' parent directory.
type Store struct {
	db   *sql.DB
	root string
}

// NewStore wraps the opened agent database over the artifact root.
func NewStore(database *sql.DB, root string) *Store {
	return &Store{db: database, root: root}
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

// HashFile computes a file's SHA-256 (the system's one hash algorithm —
// SHI rule).
func HashFile(path string) (sha string, size int64, err error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", 0, err
	}
	defer func() {
		_ = f.Close()
	}()
	hasher := sha256.New()
	n, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), n, nil
}
