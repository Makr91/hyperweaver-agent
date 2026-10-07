// Package inbox persists each person's notification rows in agent.sqlite.
package inbox

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned when the person has no notification with the requested id.
var ErrNotFound = errors.New("notification not found")

// Migrations is appended to the agent.sqlite migration list.
var Migrations = []string{
	`CREATE TABLE notifications (
		id              TEXT PRIMARY KEY,
		person          TEXT NOT NULL,
		idempotency_key TEXT,
		type            TEXT NOT NULL,
		severity        TEXT NOT NULL,
		title           TEXT NOT NULL,
		body            TEXT NOT NULL,
		navigate        TEXT NOT NULL,
		tag             TEXT NOT NULL,
		read_at         TEXT,
		created_at      TEXT NOT NULL
	);
	CREATE UNIQUE INDEX idx_notifications_person_key ON notifications (person, idempotency_key);
	CREATE INDEX idx_notifications_person_created ON notifications (person, created_at DESC);
	CREATE INDEX idx_notifications_person_read ON notifications (person, read_at);`,
}

const (
	timeLayout = "2006-01-02T15:04:05.000000000Z"
	keepRows   = 500
)

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// The events a write to a person's inbox sends on the notifications topic.
const (
	EventCreated   = "notification-created"
	EventRead      = "notification-read"
	EventUnread    = "notification-unread"
	EventDismissed = "notification-dismissed"
	EventReadAll   = "inbox-read-all"
	EventCleared   = "inbox-cleared"
)

// OriginLocal marks a row of this store; a row the identity provider's hub holds is marked hub.
const OriginLocal = "local"

// Change is one write to a person's inbox: the event it sends and the event's data.
type Change struct {
	Event string
	Data  any
}

// ReadChange is the data of notification-read.
type ReadChange struct {
	ID     any       `json:"id"`
	ReadAt time.Time `json:"read_at"`
}

// IDChange is the data of notification-unread and notification-dismissed.
type IDChange struct {
	ID any `json:"id"`
}

// ReadAllChange is the data of inbox-read-all.
type ReadAllChange struct {
	ReadAt time.Time `json:"read_at"`
}

// ClearedChange is the data of inbox-cleared.
type ClearedChange struct{}

// Store persists notifications in agent.sqlite.
type Store struct {
	db     *sql.DB
	Notify func(person string, change Change)
}

// NewStore wraps the opened agent database.
func NewStore(database *sql.DB) *Store {
	return &Store{db: database}
}

func (s *Store) notify(person string, change Change) {
	if s.Notify != nil {
		s.Notify(person, change)
	}
}

// Row is one notification as the inbox routes answer it.
type Row struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Type      string     `json:"type"`
	Severity  string     `json:"severity"`
	Navigate  string     `json:"navigate"`
	ReadAt    *time.Time `json:"read_at"`
	CreatedAt time.Time  `json:"created_at"`
	Origin    string     `json:"origin"`
}

// Write is the content of one notification to store.
type Write struct {
	IdempotencyKey string
	Type           string
	Severity       string
	Title          string
	Body           string
	Navigate       string
	Tag            string
}

const rowColumns = `id, title, body, type, severity, navigate, read_at, created_at`

func scanRow(row interface{ Scan(...any) error }) (*Row, error) {
	r := Row{Origin: OriginLocal}
	var createdAt string
	var readAt sql.NullString
	err := row.Scan(&r.ID, &r.Title, &r.Body, &r.Type, &r.Severity, &r.Navigate, &readAt, &createdAt)
	if err != nil {
		return nil, err
	}
	if r.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("notification %s: parse created_at: %w", r.ID, err)
	}
	if readAt.Valid {
		parsed, perr := time.Parse(timeLayout, readAt.String)
		if perr != nil {
			return nil, fmt.Errorf("notification %s: parse read_at: %w", r.ID, perr)
		}
		r.ReadAt = &parsed
	}
	return &r, nil
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

// Create stores one notification for the person, replacing the content of the row that already carries the write's idempotency key, and answers the row and whether it is new.
func (s *Store) Create(ctx context.Context, person string, write *Write) (row *Row, created bool, err error) {
	id, err := newID()
	if err != nil {
		return nil, false, err
	}
	var key any
	if write.IdempotencyKey != "" {
		key = write.IdempotencyKey
	}
	var storedID string
	err = s.db.QueryRowContext(ctx, `INSERT INTO notifications
		(id, person, idempotency_key, type, severity, title, body, navigate, tag, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (person, idempotency_key) DO UPDATE SET
			type = excluded.type, severity = excluded.severity, title = excluded.title,
			body = excluded.body, navigate = excluded.navigate, tag = excluded.tag
		RETURNING id`,
		id, person, key, write.Type, write.Severity, write.Title, write.Body,
		write.Navigate, write.Tag, formatTime(time.Now())).Scan(&storedID)
	if err != nil {
		return nil, false, err
	}
	if _, err = s.db.ExecContext(ctx, `DELETE FROM notifications
		WHERE person = ? AND id NOT IN (
			SELECT id FROM notifications WHERE person = ?
			ORDER BY created_at DESC, rowid DESC LIMIT ?)`,
		person, person, keepRows); err != nil {
		return nil, false, err
	}
	row, err = s.get(ctx, person, storedID)
	if err != nil {
		return nil, false, err
	}
	created = storedID == id
	if created {
		s.notify(person, Change{Event: EventCreated, Data: row})
	}
	return row, created, nil
}

func (s *Store) get(ctx context.Context, person, id string) (*Row, error) {
	row, err := scanRow(s.db.QueryRowContext(ctx,
		`SELECT `+rowColumns+` FROM notifications WHERE person = ? AND id = ?`, person, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return row, err
}

// List answers one page of the person's notifications, newest first, and how many the person has in all.
func (s *Store) List(ctx context.Context, person string, page, size int, unreadOnly bool) (rows []*Row, total int, err error) {
	var where strings.Builder
	where.WriteString(" WHERE person = ?")
	if unreadOnly {
		where.WriteString(" AND read_at IS NULL")
	}
	var count strings.Builder
	count.WriteString("SELECT COUNT(*) FROM notifications")
	count.WriteString(where.String())
	if cerr := s.db.QueryRowContext(ctx, count.String(), person).Scan(&total); cerr != nil {
		return nil, 0, cerr
	}
	var query strings.Builder
	query.WriteString("SELECT ")
	query.WriteString(rowColumns)
	query.WriteString(" FROM notifications")
	query.WriteString(where.String())
	query.WriteString(" ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?")
	result, err := s.db.QueryContext(ctx, query.String(), person, size, page*size)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = result.Close()
	}()

	rows = []*Row{}
	for result.Next() {
		row, serr := scanRow(result)
		if serr != nil {
			return nil, 0, serr
		}
		rows = append(rows, row)
	}
	return rows, total, result.Err()
}

// UnreadCount answers how many of the person's notifications are unread.
func (s *Store) UnreadCount(ctx context.Context, person string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notifications WHERE person = ? AND read_at IS NULL`, person).Scan(&n)
	return n, err
}

// MarkRead records the person's notification as read, keeping the time of an earlier read.
func (s *Store) MarkRead(ctx context.Context, person, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE notifications
		SET read_at = COALESCE(read_at, ?) WHERE person = ? AND id = ?`,
		formatTime(time.Now()), person, id)
	if err != nil {
		return err
	}
	if rerr := requireRow(res); rerr != nil {
		return rerr
	}
	row, err := s.get(ctx, person, id)
	if err != nil {
		return err
	}
	if row.ReadAt != nil {
		s.notify(person, Change{Event: EventRead, Data: ReadChange{ID: id, ReadAt: *row.ReadAt}})
	}
	return nil
}

// MarkUnread puts the person's notification back to unread.
func (s *Store) MarkUnread(ctx context.Context, person, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE notifications
		SET read_at = NULL WHERE person = ? AND id = ?`, person, id)
	if err != nil {
		return err
	}
	if rerr := requireRow(res); rerr != nil {
		return rerr
	}
	s.notify(person, Change{Event: EventUnread, Data: IDChange{ID: id}})
	return nil
}

// MarkAllRead records every unread notification of the person as read.
func (s *Store) MarkAllRead(ctx context.Context, person string) error {
	readAt := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx, `UPDATE notifications
		SET read_at = ? WHERE person = ? AND read_at IS NULL`, formatTime(readAt), person); err != nil {
		return err
	}
	s.notify(person, Change{Event: EventReadAll, Data: ReadAllChange{ReadAt: readAt}})
	return nil
}

// Delete removes the person's notification.
func (s *Store) Delete(ctx context.Context, person, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE person = ? AND id = ?`, person, id)
	if err != nil {
		return err
	}
	if rerr := requireRow(res); rerr != nil {
		return rerr
	}
	s.notify(person, Change{Event: EventDismissed, Data: IDChange{ID: id}})
	return nil
}

// DeleteAll removes every notification of the person.
func (s *Store) DeleteAll(ctx context.Context, person string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE person = ?`, person); err != nil {
		return err
	}
	s.notify(person, Change{Event: EventCleared, Data: ClearedChange{}})
	return nil
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
