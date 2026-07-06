// Package assets implements the installer file cache (architecture §13.3,
// SHI's SuperHumanFileCache merged with zoneweaver's storage-location model):
// hash-verified installer/fixpack/hotfix files under a configurable cache
// root, registered in agent.sqlite, seeded with hash EXPECTATIONS (no
// binaries), scanned on demand, downloaded as tasks with live progress, and
// mounted into machine working directories ONLY when their SHA-256 checks
// out — Mark's ruling (2026-07-06): hash verification is the point, no
// half-done implementation.
package assets

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// alog is this package's category logger (logging.categories.assets).
func alog() *slog.Logger {
	return logging.Category("assets")
}

// Kinds — SHI's file-cache types. cacheSubdir names the on-disk directory
// (SHI's installers/hotfixes/fixpacks); workdirSubdir names the mount target
// inside a machine's installers/<role>/ tree (SHI's observed working copies).
const (
	KindInstaller = "installer"
	KindFixpack   = "fixpack"
	KindHotfix    = "hotfix"
)

// ErrNotFound is returned when no artifact matches the request.
var ErrNotFound = errors.New("artifact not found")

// namePattern bounds role names and filenames kept on disk: no separators,
// no traversal, no shell-hostile input.
var (
	rolePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,254}$`)
)

// ValidRole reports whether s is usable as a cache role directory.
func ValidRole(s string) bool {
	return rolePattern.MatchString(s)
}

// ValidFilename reports whether s is usable as a cached filename.
func ValidFilename(s string) bool {
	return filenamePattern.MatchString(s) && !strings.Contains(s, "..")
}

// ValidKind reports whether s is one of the three cache kinds.
func ValidKind(s string) bool {
	return s == KindInstaller || s == KindFixpack || s == KindHotfix
}

// CacheSubdir maps a kind to its cache directory name (SHI layout:
// <cache>/<role>/<installers|fixpacks|hotfixes>/<filename>).
func CacheSubdir(kind string) string {
	switch kind {
	case KindFixpack:
		return "fixpacks"
	case KindHotfix:
		return "hotfixes"
	default:
		return "installers"
	}
}

// WorkdirSubdir maps a kind to its mount directory inside a working copy's
// installers/<role>/ tree (SHI's observed archives/fixpack/hotfix).
func WorkdirSubdir(kind string) string {
	switch kind {
	case KindFixpack:
		return "fixpack"
	case KindHotfix:
		return "hotfix"
	default:
		return "archives"
	}
}

// Migrations is the artifacts schema, appended to agent.sqlite's migration
// list (db.Open user_version tracking). expected_sha256 carries the
// EXPECTATION (initial-registry seed or HCL catalog); sha256 carries what
// the file actually hashed to when last verified. file_exists mirrors SHI's
// exists flag: expectation rows ship with no binary.
var Migrations = []string{
	`CREATE TABLE artifacts (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		role            TEXT NOT NULL,
		kind            TEXT NOT NULL,
		filename        TEXT NOT NULL,
		path            TEXT,
		sha256          TEXT,
		expected_sha256 TEXT,
		size            INTEGER NOT NULL DEFAULT 0,
		version         TEXT,
		file_exists     INTEGER NOT NULL DEFAULT 0,
		verified_at     TEXT,
		source_url      TEXT,
		created_at      TEXT NOT NULL,
		updated_at      TEXT NOT NULL,
		UNIQUE (role, kind, filename)
	);
	CREATE INDEX idx_artifacts_role_kind ON artifacts (role, kind);`,
}

// timeLayout matches the other stores' fixed-width UTC convention.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// Artifact is one cache row (the Agent API artifacts surface).
type Artifact struct {
	ID             int64      `json:"id"`
	Role           string     `json:"role"`
	Kind           string     `json:"kind"`
	Filename       string     `json:"filename"`
	Path           string     `json:"path"`
	SHA256         string     `json:"sha256"`
	ExpectedSHA256 string     `json:"expected_sha256"`
	Size           int64      `json:"size"`
	Version        string     `json:"version"`
	Exists         bool       `json:"exists"`
	VerifiedAt     *time.Time `json:"verified_at"`
	SourceURL      string     `json:"source_url"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// Verified reports whether the cached file's hash is trustworthy: it exists,
// was hashed, and matches its expectation when one is recorded.
func (a *Artifact) Verified() bool {
	if !a.Exists || a.SHA256 == "" {
		return false
	}
	return a.ExpectedSHA256 == "" || strings.EqualFold(a.SHA256, a.ExpectedSHA256)
}

// Store persists artifact rows in agent.sqlite; Dir is the cache root.
type Store struct {
	db  *sql.DB
	dir string
}

// NewStore wraps the opened agent database over the cache root.
func NewStore(database *sql.DB, dir string) *Store {
	return &Store{db: database, dir: dir}
}

// Dir returns the cache root.
func (s *Store) Dir() string {
	return s.dir
}

// PathFor computes (and containment-checks) a file's cache location.
func (s *Store) PathFor(role, kind, filename string) (string, error) {
	if !ValidRole(role) {
		return "", fmt.Errorf("role %q is not usable", role)
	}
	if !ValidKind(kind) {
		return "", fmt.Errorf("kind %q must be installer, fixpack, or hotfix", kind)
	}
	if !ValidFilename(filename) {
		return "", fmt.Errorf("filename %q is not usable", filename)
	}
	return safepath.Under(s.dir, filepath.Join(role, CacheSubdir(kind), filename))
}

const artifactColumns = `id, role, kind, filename, path, sha256, expected_sha256,
	size, version, file_exists, verified_at, source_url, created_at, updated_at`

func scanArtifact(row interface{ Scan(...any) error }) (*Artifact, error) {
	var a Artifact
	var path, sha, expected, version, sourceURL, verifiedAt sql.NullString
	var createdAt, updatedAt string
	err := row.Scan(&a.ID, &a.Role, &a.Kind, &a.Filename, &path, &sha, &expected,
		&a.Size, &version, &a.Exists, &verifiedAt, &sourceURL, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	a.Path = path.String
	a.SHA256 = sha.String
	a.ExpectedSHA256 = expected.String
	a.Version = version.String
	a.SourceURL = sourceURL.String
	if a.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("artifact %d: parse created_at: %w", a.ID, err)
	}
	if a.UpdatedAt, err = time.Parse(timeLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("artifact %d: parse updated_at: %w", a.ID, err)
	}
	if verifiedAt.Valid {
		parsed, perr := time.Parse(timeLayout, verifiedAt.String)
		if perr != nil {
			return nil, fmt.Errorf("artifact %d: parse verified_at: %w", a.ID, perr)
		}
		a.VerifiedAt = &parsed
	}
	return &a, nil
}

// ListFilter selects artifacts (GET /artifacts query parameters).
type ListFilter struct {
	Role   string
	Kind   string
	Exists *bool
}

// List returns artifacts matching the filter, role/kind/filename ascending.
func (s *Store) List(ctx context.Context, f *ListFilter) ([]*Artifact, error) {
	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(artifactColumns)
	query.WriteString(" FROM artifacts")
	clauses := []string{}
	args := []any{}
	if f.Role != "" {
		clauses = append(clauses, "role = ?")
		args = append(args, f.Role)
	}
	if f.Kind != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.Exists != nil {
		clauses = append(clauses, "file_exists = ?")
		args = append(args, *f.Exists)
	}
	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	query.WriteString(" ORDER BY role ASC, kind ASC, filename ASC")

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	list := []*Artifact{}
	for rows.Next() {
		a, serr := scanArtifact(rows)
		if serr != nil {
			return nil, serr
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// Get returns one artifact by id, or ErrNotFound.
func (s *Store) Get(ctx context.Context, id int64) (*Artifact, error) {
	a, err := scanArtifact(s.db.QueryRowContext(ctx,
		`SELECT `+artifactColumns+` FROM artifacts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// Find returns the artifact registered under (role, kind, filename), or
// ErrNotFound — the resolution the working-copy materialization performs.
func (s *Store) Find(ctx context.Context, role, kind, filename string) (*Artifact, error) {
	a, err := scanArtifact(s.db.QueryRowContext(ctx,
		`SELECT `+artifactColumns+` FROM artifacts
		 WHERE role = ? AND kind = ? AND filename = ?`, role, kind, filename))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// Ingested records a file that now exists in the cache with a fresh hash.
type Ingested struct {
	Role      string
	Kind      string
	Filename  string
	Path      string
	SHA256    string
	Size      int64
	Version   string
	SourceURL string
}

// RecordIngested upserts a cache row for a file just hashed on disk. An
// existing row keeps its expectation (and version when the ingest carries
// none) — verification compares against it.
func (s *Store) RecordIngested(ctx context.Context, in *Ingested) (*Artifact, error) {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(role, kind, filename, path, sha256, size, version, file_exists,
		 verified_at, source_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
		ON CONFLICT (role, kind, filename) DO UPDATE SET
		 path = excluded.path, sha256 = excluded.sha256, size = excluded.size,
		 version = CASE WHEN excluded.version != '' THEN excluded.version ELSE artifacts.version END,
		 file_exists = 1, verified_at = excluded.verified_at,
		 source_url = CASE WHEN excluded.source_url != '' THEN excluded.source_url ELSE artifacts.source_url END,
		 updated_at = excluded.updated_at`,
		in.Role, in.Kind, in.Filename, in.Path, in.SHA256, in.Size, in.Version,
		now, in.SourceURL, now, now)
	if err != nil {
		return nil, err
	}
	return s.Find(ctx, in.Role, in.Kind, in.Filename)
}

// SeedExpectation inserts a hash expectation (no binary) unless the entry
// already exists — SHI's initial-registry semantics.
func (s *Store) SeedExpectation(ctx context.Context, role, kind, filename, sha, version string) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(role, kind, filename, expected_sha256, version, file_exists, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT (role, kind, filename) DO NOTHING`,
		role, kind, filename, sha, version, now, now)
	return err
}

// SetExpectation records the authoritative hash for an entry (the HCL
// catalog's sha256 overwrites the expectation, SHI rule).
func (s *Store) SetExpectation(ctx context.Context, role, kind, filename, sha string) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(role, kind, filename, expected_sha256, file_exists, created_at, updated_at)
		VALUES (?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT (role, kind, filename) DO UPDATE SET
		 expected_sha256 = excluded.expected_sha256, updated_at = excluded.updated_at`,
		role, kind, filename, sha, now, now)
	return err
}

// MarkMissing flags a row whose file is gone (scan outcome). The row and its
// expectation survive — SHI keeps expectation entries with exists:false.
func (s *Store) MarkMissing(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE artifacts
		SET file_exists = 0, updated_at = ? WHERE id = ?`, formatTime(time.Now()), id)
	return err
}

// Delete removes a row, optionally deleting the cached file too.
func (s *Store) Delete(ctx context.Context, id int64, deleteFile bool) error {
	artifact, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if deleteFile && artifact.Path != "" {
		// Only files at their canonical cache location are deletable through
		// the registry — anything else was never ours to remove.
		expected, cerr := s.PathFor(artifact.Role, artifact.Kind, artifact.Filename)
		if cerr == nil && expected == artifact.Path {
			if rerr := os.Remove(artifact.Path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				return fmt.Errorf("delete cached file: %w", rerr)
			}
		}
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM artifacts WHERE id = ?`, artifact.ID)
	return err
}

// HashFile computes a file's SHA-256 (SHI's one hash algorithm).
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
