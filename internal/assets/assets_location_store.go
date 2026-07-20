package assets

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

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
