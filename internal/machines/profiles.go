package machines

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Provisioning profiles — the base's ProvisioningProfileModel ported: named,
// reusable bundles of credentials, sync folders, provisioners, and variables
// a user composes WITHOUT bundling a Hosts.yml or provisioner package (Mark's
// ruling 2026-07-07). The UI applies a profile by feeding its pieces into a
// machine's provisioner document (PUT /machines/{name}). The base's recipe_id
// is zlogin machinery and has no analog here.

// ErrProfileNotFound reports no profile with the requested id.
var ErrProfileNotFound = errors.New("provisioning profile not found")

// ErrProfileExists reports a name collision on create.
var ErrProfileExists = errors.New("provisioning profile already exists")

// ProfileMigrations is appended to the agent.sqlite migration list.
var ProfileMigrations = []string{
	`CREATE TABLE provisioning_profiles (
		id                   INTEGER PRIMARY KEY AUTOINCREMENT,
		name                 TEXT NOT NULL UNIQUE,
		description          TEXT,
		default_credentials  TEXT,
		default_sync_folders TEXT,
		default_provisioners TEXT,
		default_variables    TEXT,
		created_by           TEXT,
		created_at           TEXT NOT NULL,
		updated_at           TEXT NOT NULL
	);`,
}

// Profile is one provisioning profile row (the base's field set, minus
// recipe_id).
type Profile struct {
	ID                  int64           `json:"id"`
	Name                string          `json:"name"`
	Description         string          `json:"description,omitempty"`
	DefaultCredentials  json.RawMessage `json:"default_credentials,omitempty"`
	DefaultSyncFolders  json.RawMessage `json:"default_sync_folders,omitempty"`
	DefaultProvisioners json.RawMessage `json:"default_provisioners,omitempty"`
	DefaultVariables    json.RawMessage `json:"default_variables,omitempty"`
	CreatedBy           string          `json:"created_by,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

const profileColumns = `id, name, description, default_credentials,
	default_sync_folders, default_provisioners, default_variables, created_by,
	created_at, updated_at`

func scanProfile(row interface{ Scan(...any) error }) (*Profile, error) {
	var p Profile
	var description, credentials, folders, provisioners, variables, createdBy sql.NullString
	var createdAt, updatedAt string
	err := row.Scan(&p.ID, &p.Name, &description, &credentials, &folders,
		&provisioners, &variables, &createdBy, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	p.Description = description.String
	p.CreatedBy = createdBy.String
	for target, source := range map[*json.RawMessage]sql.NullString{
		&p.DefaultCredentials:  credentials,
		&p.DefaultSyncFolders:  folders,
		&p.DefaultProvisioners: provisioners,
		&p.DefaultVariables:    variables,
	} {
		if source.Valid {
			*target = json.RawMessage(source.String)
		}
	}
	if p.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("profile %d: parse created_at: %w", p.ID, err)
	}
	if p.UpdatedAt, err = time.Parse(timeLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("profile %d: parse updated_at: %w", p.ID, err)
	}
	return &p, nil
}

// ListProfiles returns every profile, name ascending (the base's ordering).
func (s *Store) ListProfiles(ctx context.Context) ([]*Profile, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+profileColumns+` FROM provisioning_profiles ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()
	list := []*Profile{}
	for rows.Next() {
		p, serr := scanProfile(rows)
		if serr != nil {
			return nil, serr
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// GetProfile returns one profile by id.
func (s *Store) GetProfile(ctx context.Context, id int64) (*Profile, error) {
	p, err := scanProfile(s.db.QueryRowContext(ctx,
		`SELECT `+profileColumns+` FROM provisioning_profiles WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProfileNotFound
	}
	return p, err
}

// nullableJSON maps empty raw JSON to NULL for storage.
func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateProfile inserts a profile (name-unique; ErrProfileExists on
// collision).
func (s *Store) CreateProfile(ctx context.Context, p *Profile) (*Profile, error) {
	if existing := s.db.QueryRowContext(ctx,
		`SELECT id FROM provisioning_profiles WHERE name = ?`, p.Name); existing != nil {
		var id int64
		if err := existing.Scan(&id); err == nil {
			return nil, ErrProfileExists
		}
	}
	now := formatTime(time.Now())
	result, err := s.db.ExecContext(ctx, `INSERT INTO provisioning_profiles
		(name, description, default_credentials, default_sync_folders,
		 default_provisioners, default_variables, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, nullableText(p.Description), nullableJSON(p.DefaultCredentials),
		nullableJSON(p.DefaultSyncFolders), nullableJSON(p.DefaultProvisioners),
		nullableJSON(p.DefaultVariables), nullableText(p.CreatedBy), now, now)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return s.GetProfile(ctx, id)
}

// UpdateProfile replaces a profile's fields (the caller sends the merged
// document — the handler applies the base's allowed-fields merge).
func (s *Store) UpdateProfile(ctx context.Context, p *Profile) (*Profile, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE provisioning_profiles
		SET name = ?, description = ?, default_credentials = ?,
		    default_sync_folders = ?, default_provisioners = ?,
		    default_variables = ?, created_by = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, nullableText(p.Description), nullableJSON(p.DefaultCredentials),
		nullableJSON(p.DefaultSyncFolders), nullableJSON(p.DefaultProvisioners),
		nullableJSON(p.DefaultVariables), nullableText(p.CreatedBy),
		formatTime(time.Now()), p.ID)
	if err != nil {
		return nil, err
	}
	if n, aerr := res.RowsAffected(); aerr != nil {
		return nil, aerr
	} else if n == 0 {
		return nil, ErrProfileNotFound
	}
	return s.GetProfile(ctx, p.ID)
}

// DeleteProfile removes a profile.
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM provisioning_profiles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, aerr := res.RowsAffected(); aerr != nil {
		return aerr
	} else if n == 0 {
		return ErrProfileNotFound
	}
	return nil
}
