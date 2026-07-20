package assets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

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
