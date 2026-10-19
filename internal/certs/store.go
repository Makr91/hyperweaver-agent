// Package certs persists the rows of the shared UI's vault store in agent.sqlite: certificates, authorities, requests, keys, SSH certificates, templates and the six secret kinds.
package certs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned when no row carries the requested id.
var ErrNotFound = errors.New("certificate not found")

// Migrations is appended to the agent.sqlite migration list.
var Migrations = []string{
	`CREATE TABLE certs (
		id           TEXT PRIMARY KEY,
		organization TEXT NOT NULL,
		kind         TEXT NOT NULL,
		name         TEXT NOT NULL,
		subject      TEXT NOT NULL,
		not_after    TEXT NOT NULL,
		published    INTEGER NOT NULL,
		guest_access INTEGER NOT NULL,
		created_by   TEXT NOT NULL,
		updated_at   TEXT NOT NULL,
		record       TEXT NOT NULL
	);
	CREATE INDEX idx_certs_kind_name ON certs (kind, name);
	CREATE INDEX idx_certs_created_by ON certs (created_by);`,
}

const timeLayout = "2006-01-02T15:04:05.000000000Z"

// The kinds a row carries: the vault's six and the eight secret kinds, each the shape of a credential.
const (
	KindCertificate    = "certificate"
	KindAuthority      = "authority"
	KindRequest        = "request"
	KindKey            = "key"
	KindSSHCertificate = "ssh_certificate"
	KindTemplate       = "template"
	KindPassword       = "password"
	KindAPIKey         = "api_key"
	KindBasicAuth      = "basic_auth"
	KindKeyPair        = "key_pair"
	KindOAuthClient    = "oauth_client"
	KindSSHKey         = "ssh_key"
	KindFile           = "file"
	KindCustom         = "custom"
)

// Kinds lists every kind in the order refusals name them.
var Kinds = []string{
	KindCertificate, KindAuthority, KindRequest, KindKey, KindSSHCertificate, KindTemplate,
	KindPassword, KindAPIKey, KindBasicAuth, KindKeyPair, KindOAuthClient, KindSSHKey, KindFile, KindCustom,
}

// SecretMembers lists each secret kind's members, the first one the member that stands for the row; a custom row's members are its own.
var SecretMembers = map[string][]string{
	KindPassword:    {"password"},
	KindAPIKey:      {"key", "url", "account_id"},
	KindBasicAuth:   {"url", "user", "password"},
	KindKeyPair:     {"access_key", "secret_key", "url", "region"},
	KindOAuthClient: {"client_id", "client_secret", "issuer", "scopes"},
	KindSSHKey:      {"private_key", "public_key", "passphrase"},
	KindFile:        {"bytes", "filename", "password"},
	KindCustom:      {},
}

// SecretKinds are the kinds whose record carries a secret member, the private half the agent reads.
var SecretKinds = map[string]bool{
	KindPassword: true, KindAPIKey: true, KindBasicAuth: true, KindKeyPair: true,
	KindOAuthClient: true, KindSSHKey: true, KindFile: true, KindCustom: true,
}

// ValidKind reports whether kind is one of the twelve.
func ValidKind(kind string) bool {
	for _, known := range Kinds {
		if known == kind {
			return true
		}
	}
	return false
}

// Row is one row as the routes answer it.
type Row struct {
	ID           string          `json:"id"`
	Organization string          `json:"organization"`
	Kind         string          `json:"kind"`
	Name         string          `json:"name"`
	Subject      string          `json:"subject"`
	NotAfter     string          `json:"not_after"`
	Published    bool            `json:"published"`
	IsPublic     bool            `json:"is_public"`
	GuestAccess  bool            `json:"guest_access"`
	CreatedBy    string          `json:"created_by"`
	UpdatedAt    time.Time       `json:"updated_at"`
	Record       json.RawMessage `json:"record"`
}

// Write is the content of a new row.
type Write struct {
	Organization string
	Kind         string
	Name         string
	Published    bool
	GuestAccess  bool
	Record       map[string]any
}

// Patch names the members an update changes; a nil member is left as it is.
type Patch struct {
	Name        *string
	Published   *bool
	GuestAccess *bool
	Record      map[string]any
}

// Reader is who reads: the persons a key stands for and whether the key is an admin.
type Reader struct {
	Persons []string
	Admin   bool
}

func (r Reader) holds(person string) bool {
	for _, candidate := range r.Persons {
		if candidate != "" && candidate == person {
			return true
		}
	}
	return false
}

// MayRead reports whether the reader reads the row: an admin every row, a creator their own, every signed-in person a published row.
func (r Reader) MayRead(row *Row) bool {
	return r.Admin || r.holds(row.CreatedBy) || (row.Published && len(r.Persons) > 0)
}

// MayManage reports whether the reader changes or removes the row: an admin every row, a creator their own.
func (r Reader) MayManage(row *Row) bool {
	return r.Admin || r.holds(row.CreatedBy)
}

// Store persists the rows in agent.sqlite; Notify runs after every write with the row and whether it was removed.
type Store struct {
	db     *sql.DB
	Notify func(row *Row, removed bool)
}

// NewStore wraps the opened agent database.
func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
}

func (s *Store) notify(row *Row, removed bool) {
	if s.Notify != nil {
		s.Notify(row, removed)
	}
}

const rowColumns = `id, organization, kind, name, subject, not_after, published, guest_access, created_by, updated_at, record`

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func newID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	s := hex.EncodeToString(raw)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32], nil
}

func (s *Store) scanRow(row interface{ Scan(...any) error }) (*Row, error) {
	r := Row{}
	var updatedAt, record string
	var published, guestAccess int
	err := row.Scan(&r.ID, &r.Organization, &r.Kind, &r.Name, &r.Subject, &r.NotAfter,
		&published, &guestAccess, &r.CreatedBy, &updatedAt, &record)
	if err != nil {
		return nil, err
	}
	r.Published = published != 0
	r.GuestAccess = guestAccess != 0
	if r.UpdatedAt, err = time.Parse(timeLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("certificate %s: parse updated_at: %w", r.ID, err)
	}
	r.Record = json.RawMessage(record)
	return &r, nil
}

func factsOf(record map[string]any) (subject, notAfter string) {
	facts, _ := record["facts"].(map[string]any)
	subject, _ = facts["subject_dn"].(string)
	notAfter, _ = facts["not_after"].(string)
	return subject, notAfter
}

// Create stores one row for the person and answers it.
func (s *Store) Create(ctx context.Context, person string, write *Write) (*Row, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	record := write.Record
	if record == nil {
		record = map[string]any{}
	}
	record["created_by"] = person
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	subject, notAfter := factsOf(record)
	if _, err = s.db.ExecContext(ctx, `INSERT INTO certs
		(id, organization, kind, name, subject, not_after, published, guest_access, created_by, updated_at, record)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, write.Organization, write.Kind, write.Name, subject, notAfter,
		boolInt(write.Published), boolInt(write.GuestAccess), person, formatTime(time.Now()), string(raw)); err != nil {
		return nil, err
	}
	row, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.notify(row, false)
	return row, nil
}

// Update applies the patch to the row and answers the row as stored.
func (s *Store) Update(ctx context.Context, row *Row, patch *Patch) (*Row, error) {
	name, published, guestAccess := row.Name, row.Published, row.GuestAccess
	if patch.Name != nil {
		name = *patch.Name
	}
	if patch.Published != nil {
		published = *patch.Published
	}
	if patch.GuestAccess != nil {
		guestAccess = *patch.GuestAccess
	}
	record := RecordMap(row)
	if patch.Record != nil {
		record = patch.Record
	}
	record["created_by"] = row.CreatedBy
	raw, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	subject, notAfter := factsOf(record)
	if _, err = s.db.ExecContext(ctx, `UPDATE certs
		SET name = ?, published = ?, guest_access = ?, subject = ?, not_after = ?, record = ?, updated_at = ?
		WHERE id = ?`,
		name, boolInt(published), boolInt(guestAccess), subject, notAfter, string(raw), formatTime(time.Now()), row.ID); err != nil {
		return nil, err
	}
	updated, err := s.Get(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	s.notify(updated, false)
	return updated, nil
}

// Delete removes the row.
func (s *Store) Delete(ctx context.Context, row *Row) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM certs WHERE id = ?`, row.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	s.notify(row, true)
	return nil
}

// Get answers one row by id.
func (s *Store) Get(ctx context.Context, id string) (*Row, error) {
	row, err := s.scanRow(s.db.QueryRowContext(ctx, `SELECT `+rowColumns+` FROM certs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return row, err
}

// List answers the rows the reader may read, narrowed to a kind and an organization where given, newest first.
func (s *Store) List(ctx context.Context, reader Reader, kind, organization string) ([]*Row, error) {
	clauses := []string{}
	args := []any{}
	if kind != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, kind)
	}
	if organization != "" {
		clauses = append(clauses, "organization = ?")
		args = append(args, organization)
	}
	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(rowColumns)
	query.WriteString(" FROM certs")
	if len(clauses) > 0 {
		query.WriteString(" WHERE ")
		query.WriteString(strings.Join(clauses, " AND "))
	}
	query.WriteString(" ORDER BY updated_at DESC, rowid DESC")
	result, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = result.Close()
	}()
	rows := []*Row{}
	for result.Next() {
		row, serr := s.scanRow(result)
		if serr != nil {
			return nil, serr
		}
		if reader.MayRead(row) {
			rows = append(rows, row)
		}
	}
	return rows, result.Err()
}

// FindByName answers the newest row of the kind carrying the name, ErrNotFound when none.
func (s *Store) FindByName(ctx context.Context, kind, name string) (*Row, error) {
	row, err := s.scanRow(s.db.QueryRowContext(ctx, `SELECT `+rowColumns+` FROM certs
		WHERE kind = ? AND name = ? ORDER BY updated_at DESC, rowid DESC LIMIT 1`, kind, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return row, err
}

// SetSecretMember writes one member of the row's secret.
func (s *Store) SetSecretMember(ctx context.Context, id, member string, value any) error {
	row, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	record := RecordMap(row)
	secret := Secret(row)
	secret[member] = value
	record["secret"] = secret
	_, err = s.Update(ctx, row, &Patch{Record: record})
	return err
}

// RecordMap answers the row's record as a map, empty for an unreadable one.
func RecordMap(row *Row) map[string]any {
	record := map[string]any{}
	if len(row.Record) > 0 {
		_ = json.Unmarshal(row.Record, &record)
	}
	return record
}

// Secret answers a copy of the record's secret member, empty when none.
func Secret(row *Row) map[string]any {
	held, _ := RecordMap(row)["secret"].(map[string]any)
	secret := make(map[string]any, len(held))
	for member, value := range held {
		secret[member] = value
	}
	return secret
}

// Extra answers a copy of the record's extra member, the flat map of named strings beside the secret, empty when none.
func Extra(row *Row) map[string]string {
	held, _ := RecordMap(row)["extra"].(map[string]any)
	extra := make(map[string]string, len(held))
	for member, value := range held {
		if text, isText := value.(string); isText {
			extra[member] = text
		}
	}
	return extra
}

// Profile answers the record's profile, the word naming a known service, empty when none.
func Profile(row *Row) string {
	profile, _ := RecordMap(row)["profile"].(string)
	return profile
}

// FirstMember answers the name of the member that stands for a secret kind, empty for custom and for a vault kind.
func FirstMember(kind string) string {
	members := SecretMembers[kind]
	if len(members) == 0 {
		return ""
	}
	return members[0]
}

// SecretValue answers the row's first member as text, empty for a custom row, a vault row or a member that is not a string.
func SecretValue(row *Row) string {
	member := FirstMember(row.Kind)
	if member == "" {
		return ""
	}
	value, _ := Secret(row)[member].(string)
	return value
}
