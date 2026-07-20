// Package assets implements the merged artifact system (Mark's ruling
// 2026-07-09: ONE system, zoneweaver-shaped): typed storage locations where
// iso, image, installer, fixpack, and hotfix are all location types — one
// scan, one checksum store, one wire surface. SHI's hash-expectation model
// (seeded expectations, verify-then-mount) rides on top: a file that is
// absent, unhashed, or failing verification never reaches a machine.
package assets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
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

// Artifact types — the location-type vocabulary. iso/image are zoneweaver's
// flat, extension-filtered locations; installer/fixpack/hotfix are SHI's
// role-keyed cache kinds (<location>/<role>/<file>).
const (
	KindISO       = "iso"
	KindImage     = "image"
	KindInstaller = "installer"
	KindFixpack   = "fixpack"
	KindHotfix    = "hotfix"
)

// ErrNotFound is returned when no artifact or location matches the request.
var ErrNotFound = errors.New("artifact not found")

// ErrLocationNotFound distinguishes a missing storage location.
var ErrLocationNotFound = errors.New("storage location not found")

var (
	rolePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	filenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,254}$`)
)

// ValidRole reports whether s is usable as a role directory.
func ValidRole(s string) bool {
	return rolePattern.MatchString(s)
}

// ValidFilename reports whether s is usable as a stored filename.
func ValidFilename(s string) bool {
	return filenamePattern.MatchString(s) && !strings.Contains(s, "..")
}

// ValidKind reports whether s is one of the artifact types.
func ValidKind(s string) bool {
	switch s {
	case KindISO, KindImage, KindInstaller, KindFixpack, KindHotfix:
		return true
	}
	return false
}

// RoleKeyed reports whether a type stores files under role directories
// (SHI's cache kinds) rather than flat (zoneweaver's iso/image).
func RoleKeyed(kind string) bool {
	switch kind {
	case KindInstaller, KindFixpack, KindHotfix:
		return true
	}
	return false
}

// WorkdirSubdir maps a cache kind to its mount directory inside a working
// copy's installers/<role>/ tree (SHI's observed archives/fixpack/hotfix).
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

// Migrations is the original SHI cache schema on agent.sqlite. The merge
// rebuild lives in MergeMigrations, appended at the END of the combined
// migration list (user_version tracking is positional — a mid-list insert
// re-runs every later script against an existing database).
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

// MergeMigrations is the merged-artifact-system rebuild: the locations table
// plus the artifacts rebuild (location_id, the per-location identity index
// replacing the global role/kind/filename one). Existing rows survive with a
// NULL location_id; the startup location sync adopts them into the built-in
// location of their kind.
var MergeMigrations = []string{
	`CREATE TABLE artifact_locations (
		id                 TEXT PRIMARY KEY,
		name               TEXT NOT NULL,
		path               TEXT NOT NULL UNIQUE,
		type               TEXT NOT NULL,
		enabled            INTEGER NOT NULL DEFAULT 1,
		source             TEXT NOT NULL DEFAULT 'config',
		config_hash        TEXT,
		file_count         INTEGER NOT NULL DEFAULT 0,
		total_size         INTEGER NOT NULL DEFAULT 0,
		last_scan_at       TEXT,
		scan_errors        INTEGER NOT NULL DEFAULT 0,
		last_error_message TEXT,
		created_at         TEXT NOT NULL,
		updated_at         TEXT NOT NULL
	);
	CREATE INDEX idx_artifact_locations_type ON artifact_locations (type);
	CREATE TABLE artifacts_merged (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		location_id     TEXT REFERENCES artifact_locations (id),
		role            TEXT NOT NULL DEFAULT '',
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
		updated_at      TEXT NOT NULL
	);
	INSERT INTO artifacts_merged
		(role, kind, filename, path, sha256, expected_sha256, size, version,
		 file_exists, verified_at, source_url, created_at, updated_at)
	SELECT role, kind, filename, path, sha256, expected_sha256, size, version,
		 file_exists, verified_at, source_url, created_at, updated_at
	FROM artifacts;
	DROP TABLE artifacts;
	ALTER TABLE artifacts_merged RENAME TO artifacts;
	CREATE UNIQUE INDEX unique_artifact_identity ON artifacts (location_id, role, kind, filename);
	CREATE INDEX idx_artifacts_role_kind ON artifacts (role, kind);
	CREATE INDEX idx_artifacts_location ON artifacts (location_id);`,
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

// Artifact is one artifact registry row (zoneweaver's Artifact shape with
// the SHI extras alongside). checksum is what the file actually hashed to
// when last verified; expected_sha256 is the recorded expectation (bundled
// registry seed, caller-supplied, or the HCL catalog). file_exists:false rows
// are expectations awaiting their binary (SHI's model).
type Artifact struct {
	ID         int64  `json:"id"`
	LocationID string `json:"storage_location_id"`
	// Installer-family rows only — the role directory
	Role     string `json:"role,omitempty"`
	Kind     string `json:"file_type"`
	Filename string `json:"filename"`
	// File location (empty on expectation-only rows)
	Path string `json:"path"`
	// The file's actual SHA-256
	SHA256         string     `json:"checksum"`
	ExpectedSHA256 string     `json:"expected_sha256,omitempty"`
	Size           int64      `json:"size"`
	Version        string     `json:"version,omitempty"`
	Exists         bool       `json:"file_exists"`
	VerifiedAt     *time.Time `json:"last_verified"`
	SourceURL      string     `json:"source_url,omitempty"`
	CreatedAt      time.Time  `json:"discovered_at"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// Verified reports whether the file's hash is trustworthy: it exists, was
// hashed, and matches its expectation when one is recorded.
func (a *Artifact) Verified() bool {
	if !a.Exists || a.SHA256 == "" {
		return false
	}
	return a.ExpectedSHA256 == "" || strings.EqualFold(a.SHA256, a.ExpectedSHA256)
}

// ChecksumVerified is the wire's tri-state (zoneweaver's checksum_verified):
// true = matches the expectation, false = mismatch, nil = nothing to verify
// against.
func (a *Artifact) ChecksumVerified() *bool {
	if !a.Exists || a.SHA256 == "" || a.ExpectedSHA256 == "" {
		return nil
	}
	v := strings.EqualFold(a.SHA256, a.ExpectedSHA256)
	return &v
}

// Extension returns the filename's lowercase extension.
func (a *Artifact) Extension() string {
	return strings.ToLower(filepath.Ext(a.Filename))
}

// MimeType resolves the artifact's MIME type from its extension.
func (a *Artifact) MimeType() string {
	switch a.Extension() {
	case ".iso":
		return "application/x-iso9660-image"
	case ".vmdk", ".vdi", ".qcow2", ".raw", ".img":
		return "application/octet-stream"
	}
	if t := mime.TypeByExtension(a.Extension()); t != "" {
		return t
	}
	return "application/octet-stream"
}

// Location is one typed storage location (zoneweaver's
// artifact_storage_locations shape). source builtin = the five
// always-present locations under artifact_storage.dir (never deletable —
// disable instead); source config = artifact_storage.paths[] entries, which
// the storage-path API also creates and persists back into config.yaml.
type Location struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	Type       string     `json:"type"`
	Enabled    bool       `json:"enabled"`
	Source     string     `json:"source"`
	ConfigHash string     `json:"config_hash,omitempty"`
	FileCount  int64      `json:"file_count"`
	TotalSize  int64      `json:"total_size"`
	LastScanAt *time.Time `json:"last_scan_at"`
	// Consecutive scan failures
	ScanErrors int       `json:"scan_errors"`
	LastError  string    `json:"last_error_message,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
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

// ---- locations ----

const locationColumns = `id, name, path, type, enabled, source, config_hash,
	file_count, total_size, last_scan_at, scan_errors, last_error_message,
	created_at, updated_at`

func scanLocation(row interface{ Scan(...any) error }) (*Location, error) {
	var l Location
	var configHash, lastScan, lastError sql.NullString
	var createdAt, updatedAt string
	err := row.Scan(&l.ID, &l.Name, &l.Path, &l.Type, &l.Enabled, &l.Source,
		&configHash, &l.FileCount, &l.TotalSize, &lastScan, &l.ScanErrors,
		&lastError, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	l.ConfigHash = configHash.String
	l.LastError = lastError.String
	if l.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("location %s: parse created_at: %w", l.ID, err)
	}
	if l.UpdatedAt, err = time.Parse(timeLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("location %s: parse updated_at: %w", l.ID, err)
	}
	if lastScan.Valid {
		parsed, perr := time.Parse(timeLayout, lastScan.String)
		if perr != nil {
			return nil, fmt.Errorf("location %s: parse last_scan_at: %w", l.ID, perr)
		}
		l.LastScanAt = &parsed
	}
	return &l, nil
}

// LocationFilter selects locations (GET /artifacts/storage/paths).
type LocationFilter struct {
	Type    string
	Enabled *bool
}

// ListLocations returns locations matching the filter, type then name
// ascending (zoneweaver's ordering).
func (s *Store) ListLocations(ctx context.Context, f *LocationFilter) ([]*Location, error) {
	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(locationColumns)
	query.WriteString(" FROM artifact_locations")
	clauses := []string{}
	args := []any{}
	if f.Type != "" {
		clauses = append(clauses, "type = ?")
		args = append(args, f.Type)
	}
	if f.Enabled != nil {
		clauses = append(clauses, "enabled = ?")
		args = append(args, *f.Enabled)
	}
	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	query.WriteString(" ORDER BY type ASC, name ASC")

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	list := []*Location{}
	for rows.Next() {
		l, serr := scanLocation(rows)
		if serr != nil {
			return nil, serr
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

// GetLocation returns one location by id, or ErrLocationNotFound.
func (s *Store) GetLocation(ctx context.Context, id string) (*Location, error) {
	l, err := scanLocation(s.db.QueryRowContext(ctx,
		`SELECT `+locationColumns+` FROM artifact_locations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLocationNotFound
	}
	return l, err
}

// FindLocationByPath returns the location registered at path, or
// ErrLocationNotFound.
func (s *Store) FindLocationByPath(ctx context.Context, path string) (*Location, error) {
	l, err := scanLocation(s.db.QueryRowContext(ctx,
		`SELECT `+locationColumns+` FROM artifact_locations WHERE path = ?`, path))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLocationNotFound
	}
	return l, err
}

// DefaultLocation returns the enabled location of a type, built-in first —
// where kind-addressed flows (HCL downloads, expectation seeds) land.
func (s *Store) DefaultLocation(ctx context.Context, kind string) (*Location, error) {
	l, err := scanLocation(s.db.QueryRowContext(ctx,
		`SELECT `+locationColumns+` FROM artifact_locations
		 WHERE type = ? AND enabled = 1
		 ORDER BY CASE source WHEN 'builtin' THEN 0 ELSE 1 END, created_at ASC
		 LIMIT 1`, kind))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLocationNotFound
	}
	return l, err
}

// NewLocation describes a location to insert.
type NewLocation struct {
	Name       string
	Path       string
	Type       string
	Enabled    bool
	Source     string
	ConfigHash string
}

// CreateLocation inserts a location row.
func (s *Store) CreateLocation(ctx context.Context, nl *NewLocation) (*Location, error) {
	id, err := newLocationID()
	if err != nil {
		return nil, err
	}
	now := formatTime(time.Now())
	_, err = s.db.ExecContext(ctx, `INSERT INTO artifact_locations
		(id, name, path, type, enabled, source, config_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, nl.Name, nl.Path, nl.Type, nl.Enabled, nl.Source, nl.ConfigHash, now, now)
	if err != nil {
		return nil, err
	}
	return s.GetLocation(ctx, id)
}

// UpdateLocation applies the mutable fields (PUT /artifacts/storage/paths/:id
// — zoneweaver updates name and enabled only). Nil fields keep their value
// (COALESCE against the NULL the nil pointer binds).
func (s *Store) UpdateLocation(ctx context.Context, id string, name *string, enabled *bool) (*Location, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE artifact_locations SET
		name = COALESCE(?, name),
		enabled = COALESCE(?, enabled),
		updated_at = ?
		WHERE id = ?`, name, enabled, formatTime(time.Now()), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrLocationNotFound
	}
	return s.GetLocation(ctx, id)
}

// DeleteLocation removes a location row and its artifact rows.
func (s *Store) DeleteLocation(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM artifacts WHERE location_id = ?`, id); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM artifact_locations WHERE id = ?`, id)
	return err
}

// SetLocationScanResult records a scan's outcome on the location row.
func (s *Store) SetLocationScanResult(ctx context.Context, id string, scanErr error) error {
	now := formatTime(time.Now())
	if scanErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE artifact_locations
			SET scan_errors = scan_errors + 1, last_error_message = ?, updated_at = ?
			WHERE id = ?`, scanErr.Error(), now, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE artifact_locations
		SET last_scan_at = ?, scan_errors = 0, last_error_message = NULL, updated_at = ?
		WHERE id = ?`, now, now, id)
	return err
}

// RefreshLocationStats recomputes the cached file_count/total_size.
func (s *Store) RefreshLocationStats(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE artifact_locations SET
		file_count = (SELECT COUNT(*) FROM artifacts WHERE location_id = ? AND file_exists = 1),
		total_size = COALESCE((SELECT SUM(size) FROM artifacts WHERE location_id = ? AND file_exists = 1), 0),
		updated_at = ?
		WHERE id = ?`, id, id, formatTime(time.Now()), id)
	return err
}

// ---- artifacts ----

const artifactColumns = `id, location_id, role, kind, filename, path, sha256,
	expected_sha256, size, version, file_exists, verified_at, source_url,
	created_at, updated_at`

func scanArtifact(row interface{ Scan(...any) error }) (*Artifact, error) {
	var a Artifact
	var locationID, path, sha, expected, version, sourceURL, verifiedAt sql.NullString
	var createdAt, updatedAt string
	err := row.Scan(&a.ID, &locationID, &a.Role, &a.Kind, &a.Filename, &path,
		&sha, &expected, &a.Size, &version, &a.Exists, &verifiedAt, &sourceURL,
		&createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	a.LocationID = locationID.String
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
	Kind       string
	LocationID string
	Role       string
	Search     string
	Exists     *bool
	SortBy     string // filename | size | discovered_at
	SortOrder  string // asc | desc
	Limit      int
	Offset     int
}

func (f *ListFilter) where(query *strings.Builder) []any {
	clauses := []string{}
	args := []any{}
	if f.Kind != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, f.Kind)
	}
	if f.LocationID != "" {
		clauses = append(clauses, "location_id = ?")
		args = append(args, f.LocationID)
	}
	if f.Role != "" {
		clauses = append(clauses, "role = ?")
		args = append(args, f.Role)
	}
	if f.Search != "" {
		clauses = append(clauses, "filename LIKE ? ESCAPE '\\'")
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(f.Search)
		args = append(args, "%"+escaped+"%")
	}
	if f.Exists != nil {
		clauses = append(clauses, "file_exists = ?")
		args = append(args, *f.Exists)
	}
	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	return args
}

// List returns artifacts matching the filter with zoneweaver's paging.
func (s *Store) List(ctx context.Context, f *ListFilter) ([]*Artifact, error) {
	sortColumn := "filename"
	switch f.SortBy {
	case "size":
		sortColumn = "size"
	case "discovered_at":
		sortColumn = "created_at"
	}
	direction := "ASC"
	if strings.EqualFold(f.SortOrder, "desc") {
		direction = "DESC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}

	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(artifactColumns)
	query.WriteString(" FROM artifacts")
	args := f.where(&query)
	query.WriteString(" ORDER BY ")
	query.WriteString(sortColumn)
	query.WriteString(" ")
	query.WriteString(direction)
	query.WriteString(" LIMIT ? OFFSET ?")
	args = append(args, limit, f.Offset)

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

// Count returns how many artifacts match the filter (the pagination total).
func (s *Store) Count(ctx context.Context, f *ListFilter) (int, error) {
	var query strings.Builder
	query.WriteString("SELECT COUNT(*) FROM artifacts")
	args := f.where(&query)
	var n int
	err := s.db.QueryRowContext(ctx, query.String(), args...).Scan(&n)
	return n, err
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

// Find returns the artifact registered under (role, kind, filename) — the
// pipeline's installer-mount resolution. Rows whose file exists win.
func (s *Store) Find(ctx context.Context, role, kind, filename string) (*Artifact, error) {
	a, err := scanArtifact(s.db.QueryRowContext(ctx,
		`SELECT `+artifactColumns+` FROM artifacts
		 WHERE role = ? AND kind = ? AND filename = ?
		 ORDER BY file_exists DESC, id ASC LIMIT 1`, role, kind, filename))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// FindByKindFilename resolves a filename within a type across every enabled
// location — the cdroms[] cached-ISO-by-name lookup. Existing, verified rows
// win.
func (s *Store) FindByKindFilename(ctx context.Context, kind, filename string) (*Artifact, error) {
	a, err := scanArtifact(s.db.QueryRowContext(ctx,
		`SELECT `+artifactColumns+` FROM artifacts
		 WHERE kind = ? AND filename = ? AND file_exists = 1
		   AND location_id IN (SELECT id FROM artifact_locations WHERE enabled = 1)
		 ORDER BY id ASC LIMIT 1`, kind, filename))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ListByLocation returns every artifact row of a location (scan input).
func (s *Store) ListByLocation(ctx context.Context, locationID string) ([]*Artifact, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+artifactColumns+` FROM artifacts WHERE location_id = ?`, locationID)
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

// Ingested records a file that now exists with a fresh hash.
type Ingested struct {
	LocationID string
	Role       string
	Kind       string
	Filename   string
	Path       string
	SHA256     string
	Size       int64
	Version    string
	SourceURL  string
}

// RecordIngested upserts a row for a file just hashed on disk. An existing
// row keeps its expectation (and version/source when the ingest carries
// none).
func (s *Store) RecordIngested(ctx context.Context, in *Ingested) (*Artifact, error) {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(location_id, role, kind, filename, path, sha256, size, version,
		 file_exists, verified_at, source_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
		ON CONFLICT (location_id, role, kind, filename) DO UPDATE SET
		 path = excluded.path, sha256 = excluded.sha256, size = excluded.size,
		 version = CASE WHEN excluded.version != '' THEN excluded.version ELSE artifacts.version END,
		 file_exists = 1, verified_at = excluded.verified_at,
		 source_url = CASE WHEN excluded.source_url != '' THEN excluded.source_url ELSE artifacts.source_url END,
		 updated_at = excluded.updated_at`,
		in.LocationID, in.Role, in.Kind, in.Filename, in.Path, in.SHA256,
		in.Size, in.Version, now, in.SourceURL, now, now)
	if err != nil {
		return nil, err
	}
	a, err := scanArtifact(s.db.QueryRowContext(ctx,
		`SELECT `+artifactColumns+` FROM artifacts
		 WHERE location_id = ? AND role = ? AND kind = ? AND filename = ?`,
		in.LocationID, in.Role, in.Kind, in.Filename))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// SeedExpectation inserts a hash expectation (no binary) unless the entry
// already exists — SHI's initial-registry semantics.
func (s *Store) SeedExpectation(ctx context.Context, locationID, role, kind, filename, sha, version string) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(location_id, role, kind, filename, expected_sha256, version, file_exists, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT (location_id, role, kind, filename) DO NOTHING`,
		locationID, role, kind, filename, sha, version, now, now)
	return err
}

// SetExpectation records the authoritative hash for an entry (the HCL
// catalog's sha256 overwrites the expectation — SHI rule).
func (s *Store) SetExpectation(ctx context.Context, locationID, role, kind, filename, sha string) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(location_id, role, kind, filename, expected_sha256, file_exists, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT (location_id, role, kind, filename) DO UPDATE SET
		 expected_sha256 = excluded.expected_sha256, updated_at = excluded.updated_at`,
		locationID, role, kind, filename, sha, now, now)
	return err
}

// MarkMissing flags a row whose file is gone. The row and its expectation
// survive (SHI keeps expectation entries with exists:false).
func (s *Store) MarkMissing(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE artifacts
		SET file_exists = 0, updated_at = ? WHERE id = ?`, formatTime(time.Now()), id)
	return err
}

// TouchVerified refreshes last_verified (stream-download bookkeeping).
func (s *Store) TouchVerified(ctx context.Context, id int64) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `UPDATE artifacts
		SET verified_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
	return err
}

// UpdatePlacement rewrites a row's location and path (the move executor's
// database half).
func (s *Store) UpdatePlacement(ctx context.Context, id int64, locationID, path string) error {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `UPDATE artifacts
		SET location_id = ?, path = ?, verified_at = ?, updated_at = ? WHERE id = ?`,
		locationID, path, now, now, id)
	return err
}

// DeleteRow removes an artifact row (files are the executors' business).
func (s *Store) DeleteRow(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM artifacts WHERE id = ?`, id)
	return err
}

// AdoptOrphanRows attaches location-less rows (pre-merge SHI cache rows) to
// the built-in location of their kind. Paths from the old layout go stale;
// the location's next scan marks them missing and re-registers what it
// finds — expectations ride through untouched.
func (s *Store) AdoptOrphanRows(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT kind FROM artifacts WHERE location_id IS NULL`)
	if err != nil {
		return err
	}
	kinds := []string{}
	for rows.Next() {
		var kind string
		if serr := rows.Scan(&kind); serr != nil {
			_ = rows.Close()
			return serr
		}
		kinds = append(kinds, kind)
	}
	if cerr := rows.Close(); cerr != nil {
		return cerr
	}
	for _, kind := range kinds {
		location, lerr := s.DefaultLocation(ctx, kind)
		if lerr != nil {
			alog().Warn("orphan artifact rows have no location for their type", "type", kind)
			continue
		}
		if _, uerr := s.db.ExecContext(ctx, `UPDATE artifacts
			SET location_id = ?, updated_at = ? WHERE location_id IS NULL AND kind = ?`,
			location.ID, formatTime(time.Now()), kind); uerr != nil {
			return uerr
		}
	}
	return nil
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
