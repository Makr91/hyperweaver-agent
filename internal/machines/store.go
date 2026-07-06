package machines

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned when no machine has the requested name.
var ErrNotFound = errors.New("machine not found")

// Migrations is the agent.sqlite schema (applied by db.Open via user_version
// tracking). backing/home/uuid are this agent's dual-path fields; spec
// (migration 2) is the machine-create request document, kept apart from the
// live configuration so discovery refreshes never clobber the user's intent.
var Migrations = []string{
	`CREATE TABLE machines (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		name            TEXT NOT NULL UNIQUE,
		host            TEXT NOT NULL,
		status          TEXT NOT NULL DEFAULT 'configured',
		backing         TEXT NOT NULL DEFAULT 'vbox',
		home            TEXT,
		uuid            TEXT,
		server_id       TEXT UNIQUE,
		is_orphaned     INTEGER NOT NULL DEFAULT 0,
		auto_discovered INTEGER NOT NULL DEFAULT 0,
		last_seen       TEXT,
		notes           TEXT,
		tags            TEXT,
		configuration   TEXT,
		created_at      TEXT NOT NULL,
		updated_at      TEXT NOT NULL
	);
	CREATE INDEX idx_machines_status ON machines (status);
	CREATE INDEX idx_machines_uuid ON machines (uuid);`,
	`ALTER TABLE machines ADD COLUMN spec TEXT;`,
}

// timeLayout is the stored timestamp format: fixed-width UTC so lexicographic
// order is chronological (same convention as the tasks store).
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// Store persists machines in agent.sqlite.
type Store struct {
	db *sql.DB
}

// NewStore wraps the opened agent database.
func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
}

const machineColumns = `id, name, host, status, backing, home, uuid, server_id,
	is_orphaned, auto_discovered, last_seen, notes, tags, configuration, spec,
	created_at, updated_at`

// scanMachine reads one machine row from any row scanner.
func scanMachine(row interface{ Scan(...any) error }) (*Machine, error) {
	var m Machine
	var createdAt, updatedAt string
	var lastSeen, tags, configuration, spec sql.NullString
	err := row.Scan(&m.ID, &m.Name, &m.Host, &m.Status, &m.Backing, &m.Home,
		&m.UUID, &m.ServerID, &m.IsOrphaned, &m.AutoDiscovered, &lastSeen,
		&m.Notes, &tags, &configuration, &spec, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if m.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("machine %s: parse created_at: %w", m.Name, err)
	}
	if m.UpdatedAt, err = time.Parse(timeLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("machine %s: parse updated_at: %w", m.Name, err)
	}
	if lastSeen.Valid {
		parsed, perr := time.Parse(timeLayout, lastSeen.String)
		if perr != nil {
			return nil, fmt.Errorf("machine %s: parse last_seen: %w", m.Name, perr)
		}
		m.LastSeen = &parsed
	}
	if tags.Valid {
		m.Tags = json.RawMessage(tags.String)
	}
	if configuration.Valid {
		m.Configuration = json.RawMessage(configuration.String)
	}
	if spec.Valid {
		m.Spec = json.RawMessage(spec.String)
	}
	return &m, nil
}

// ListFilter selects machines (the GET /machines query parameters).
type ListFilter struct {
	Status   string
	Orphaned *bool
}

// List returns machines matching the filter, name ascending. Tag filtering
// happens in the handler (tags is a JSON column — Node-agent parity).
func (s *Store) List(ctx context.Context, f *ListFilter) ([]*Machine, error) {
	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(machineColumns)
	query.WriteString(" FROM machines")
	clauses := []string{}
	args := []any{}
	if f.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, f.Status)
	}
	if f.Orphaned != nil {
		clauses = append(clauses, "is_orphaned = ?")
		args = append(args, *f.Orphaned)
	}
	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	query.WriteString(" ORDER BY name ASC")

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	list := []*Machine{}
	for rows.Next() {
		m, serr := scanMachine(rows)
		if serr != nil {
			return nil, serr
		}
		list = append(list, m)
	}
	return list, rows.Err()
}

// Get returns the machine with the given name, or ErrNotFound.
func (s *Store) Get(ctx context.Context, name string) (*Machine, error) {
	m, err := scanMachine(s.db.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// Discovered is what one reconciliation observation carries into the store.
type Discovered struct {
	Name          string
	Host          string
	Status        string
	Backing       string
	Home          *string
	UUID          string
	Configuration json.RawMessage
}

// UpsertDiscovered records a machine seen on the system. The row to refresh
// is matched by UUID first, then by vagrant home, then by name — a
// provisioned machine's VirtualBox name is Hosts.rb's own (never the
// registry name), so the UUID and the working directory are what tie the VM
// back to its row; matched rows keep their name and user data (notes, tags,
// server_id, spec — the Node agent's preserveUserConfig semantics). Returns
// true when the machine was newly discovered.
func (s *Store) UpsertDiscovered(ctx context.Context, d *Discovered) (bool, error) {
	now := formatTime(time.Now())
	var configuration any
	if d.Configuration != nil {
		configuration = string(d.Configuration)
	}

	// One refresh statement per match key; the SET list never touches name.
	refresh := `UPDATE machines
		SET host = ?, status = ?, backing = ?, home = COALESCE(?, home),
		    uuid = ?, is_orphaned = 0, last_seen = ?,
		    configuration = COALESCE(?, configuration), updated_at = ?`
	args := []any{d.Host, d.Status, d.Backing, d.Home, d.UUID, now, configuration, now}

	matches := []struct {
		where string
		key   any
		skip  bool
	}{
		{where: " WHERE uuid = ?", key: d.UUID, skip: d.UUID == ""},
		// A created-but-never-started row claims its VM on first sight: the
		// working directory is the join key while the UUID is still unknown.
		{where: " WHERE uuid IS NULL AND home = ?", key: d.Home, skip: d.Home == nil},
		{where: " WHERE name = ?", key: d.Name, skip: false},
	}
	for _, match := range matches {
		if match.skip {
			continue
		}
		res, err := s.db.ExecContext(ctx, refresh+match.where, append(append([]any{}, args...), match.key)...)
		if err != nil {
			return false, err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return false, err
		}
		if affected > 0 {
			return false, nil
		}
	}

	_, err := s.db.ExecContext(ctx, `INSERT INTO machines
		(name, host, status, backing, home, uuid, is_orphaned, auto_discovered,
		 last_seen, configuration, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?)`,
		d.Name, d.Host, d.Status, d.Backing, d.Home, d.UUID, now, configuration, now, now)
	if err != nil {
		return false, err
	}
	return true, nil
}

// NewMachine is a machine-create request row (POST /machines): a registry
// entry with the user's spec and working directory — no VM until first
// start (SHI's clone model).
type NewMachine struct {
	Name     string
	Host     string
	Home     string
	ServerID string
	Spec     json.RawMessage
}

// Create inserts a provisioned-machine row in status configured, backing
// vagrant.
func (s *Store) Create(ctx context.Context, nm *NewMachine) (*Machine, error) {
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO machines
		(name, host, status, backing, home, server_id, is_orphaned,
		 auto_discovered, spec, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?)`,
		nm.Name, nm.Host, StatusConfigured, BackingVagrant, nm.Home, nm.ServerID,
		string(nm.Spec), now, now)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, nm.Name)
}

// SetSpec replaces a machine's creation spec (PUT /machines/{name} — the
// change materializes on the next start).
func (s *Store) SetSpec(ctx context.Context, name string, spec json.RawMessage) error {
	res, err := s.db.ExecContext(ctx, `UPDATE machines
		SET spec = ?, updated_at = ? WHERE name = ?`,
		string(spec), formatTime(time.Now()), name)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// SetUUID records the VirtualBox UUID vagrant's first up produced.
func (s *Store) SetUUID(ctx context.Context, name, uuid string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE machines
		SET uuid = ?, updated_at = ? WHERE name = ?`,
		uuid, formatTime(time.Now()), name)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// MarkMissing flags every machine NOT in seenNames as orphaned — it exists
// in the registry but not on the system. Rows that never had a VM
// (configured, no uuid) are left alone: absence is their normal state.
func (s *Store) MarkMissing(ctx context.Context, seenNames []string) (int64, error) {
	now := formatTime(time.Now())
	var query strings.Builder
	query.WriteString(`UPDATE machines SET is_orphaned = 1, updated_at = ?
		WHERE is_orphaned = 0 AND uuid IS NOT NULL`)
	args := []any{now}
	if len(seenNames) > 0 {
		query.WriteString(" AND name NOT IN (?")
		query.WriteString(strings.Repeat(", ?", len(seenNames)-1))
		query.WriteString(")")
		for _, name := range seenNames {
			args = append(args, name)
		}
	}
	res, err := s.db.ExecContext(ctx, query.String(), args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SetStatus records a machine's live status (targeted refresh after a
// lifecycle operation, SHI parity).
func (s *Store) SetStatus(ctx context.Context, name, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE machines
		SET status = ?, last_seen = ?, updated_at = ? WHERE name = ?`,
		status, formatTime(time.Now()), formatTime(time.Now()), name)
	return err
}

// SetOrphaned flags or clears a machine's orphan state.
func (s *Store) SetOrphaned(ctx context.Context, name string, orphaned bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE machines
		SET is_orphaned = ?, updated_at = ? WHERE name = ?`,
		orphaned, formatTime(time.Now()), name)
	return err
}

// SetNotes updates a machine's free-form notes (nil clears).
func (s *Store) SetNotes(ctx context.Context, name string, notes *string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE machines
		SET notes = ?, updated_at = ? WHERE name = ?`,
		notes, formatTime(time.Now()), name)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// SetTags updates a machine's tags (nil clears).
func (s *Store) SetTags(ctx context.Context, name string, tags json.RawMessage) error {
	var value any
	if tags != nil {
		value = string(tags)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE machines
		SET tags = ?, updated_at = ? WHERE name = ?`,
		value, formatTime(time.Now()), name)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// Delete removes a machine row (the delete executor's final step).
func (s *Store) Delete(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM machines WHERE name = ?`, name)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func requireRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UsedServerID is one row of the GET /machines/ids listing.
type UsedServerID struct {
	ServerID    string `json:"server_id"`
	MachineName string `json:"machine_name"`
	Status      string `json:"status"`
}

// UsedServerIDs lists machines that carry a server_id, ascending.
func (s *Store) UsedServerIDs(ctx context.Context) ([]UsedServerID, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT server_id, name, status
		FROM machines WHERE server_id IS NOT NULL ORDER BY server_id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	used := []UsedServerID{}
	for rows.Next() {
		var u UsedServerID
		if serr := rows.Scan(&u.ServerID, &u.MachineName, &u.Status); serr != nil {
			return nil, serr
		}
		used = append(used, u)
	}
	return used, rows.Err()
}

// NextServerID computes max(MAX+1, start) over stored server_ids,
// zero-padded to 4 digits (the Node agent's generateNextServerId with its
// zones.server_id_start floor). server_id defaults to auto-assigned per
// design D-G.
func (s *Store) NextServerID(ctx context.Context, start int) (string, error) {
	var highest sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(CAST(server_id AS INTEGER))
		FROM machines WHERE server_id IS NOT NULL`).Scan(&highest)
	if err != nil {
		return "", err
	}
	next := int64(start)
	if highest.Valid && highest.Int64 >= next {
		next = highest.Int64 + 1
	}
	return fmt.Sprintf("%04d", next), nil
}
