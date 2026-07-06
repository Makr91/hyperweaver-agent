// Package db opens the agent's SQLite databases (modernc.org/sqlite — pure
// Go, keeps CGO_ENABLED=0 builds) and applies schema migrations tracked by
// SQLite's user_version pragma. Storage is split across database files by
// write-contention domain (architecture D-A): tasks.sqlite carries the task
// queue and its streamed output (the highest write volume) so it never
// contends with agent.sqlite's low-churn core state (machines, templates,
// artifacts — arriving in later phases). Both live under the data directory,
// 0600.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Options carries the configurable session pragmas (the Node agent's
// database.sqlite_options, minus its Sequelize pool/retry blocks — this
// agent runs one pooled connection per database, single-writer by
// construction).
type Options struct {
	JournalMode       string
	Synchronous       string
	CacheSizeMB       int
	TempStore         string
	MmapSizeMB        int
	BusyTimeoutMS     int
	WALAutocheckpoint int
	Optimize          bool
}

// The string-valued pragmas are selected as COMPLETE literal statements —
// configuration input never becomes SQL text, not even by concatenation.
// Config validation has already rejected anything outside these
// vocabularies; an unknown value here is a programming error surfaced as an
// open failure.

func journalModePragma(mode string) (string, error) {
	switch strings.ToUpper(mode) {
	case "DELETE":
		return "PRAGMA journal_mode=DELETE", nil
	case "TRUNCATE":
		return "PRAGMA journal_mode=TRUNCATE", nil
	case "PERSIST":
		return "PRAGMA journal_mode=PERSIST", nil
	case "MEMORY":
		return "PRAGMA journal_mode=MEMORY", nil
	case "WAL":
		return "PRAGMA journal_mode=WAL", nil
	case "OFF":
		return "PRAGMA journal_mode=OFF", nil
	default:
		return "", fmt.Errorf("unknown journal_mode %q", mode)
	}
}

func synchronousPragma(mode string) (string, error) {
	switch strings.ToUpper(mode) {
	case "OFF":
		return "PRAGMA synchronous=OFF", nil
	case "NORMAL":
		return "PRAGMA synchronous=NORMAL", nil
	case "FULL":
		return "PRAGMA synchronous=FULL", nil
	case "EXTRA":
		return "PRAGMA synchronous=EXTRA", nil
	default:
		return "", fmt.Errorf("unknown synchronous %q", mode)
	}
}

func tempStorePragma(store string) (string, error) {
	switch strings.ToUpper(store) {
	case "DEFAULT":
		return "PRAGMA temp_store=DEFAULT", nil
	case "FILE":
		return "PRAGMA temp_store=FILE", nil
	case "MEMORY":
		return "PRAGMA temp_store=MEMORY", nil
	default:
		return "", fmt.Errorf("unknown temp_store %q", store)
	}
}

// Open opens (creating if needed) the SQLite database at path, applies the
// configured session pragmas, and applies migrations. Each migration is one
// SQL script; user_version records how many have been applied, so a database
// created by an older build is upgraded by running only the scripts it has
// not seen.
func Open(ctx context.Context, path string, opts *Options, migrations []string) (*sql.DB, error) {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return nil, err
	}
	if merr := os.MkdirAll(filepath.Dir(clean), 0o700); merr != nil {
		return nil, fmt.Errorf("create data dir: %w", merr)
	}

	// Pre-create the file 0600 so it never exists with the driver's default
	// (wider) permissions. SQLite's -wal/-shm sidecars inherit this mode.
	handle, err := os.OpenFile(filepath.Clean(clean), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create database %s: %w", clean, err)
	}
	if cerr := handle.Close(); cerr != nil {
		return nil, cerr
	}
	if runtime.GOOS != "windows" {
		if cherr := os.Chmod(clean, 0o600); cherr != nil {
			return nil, cherr
		}
	}

	database, err := sql.Open("sqlite", clean)
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", clean, err)
	}

	// One connection: SQLite is single-writer anyway, and a single pooled
	// connection makes the session pragmas below apply to every statement
	// while eliminating SQLITE_BUSY between the agent's own goroutines.
	database.SetMaxOpenConns(1)

	if err := configure(ctx, database, opts); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("configure database %s: %w", clean, err)
	}
	if err := migrate(ctx, database, migrations); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("migrate database %s: %w", clean, err)
	}
	return database, nil
}

// configure applies the session pragmas from the configured sqlite_options
// (the Node agent's config/Database.js pragma block) plus enforced foreign
// keys. String pragma values select complete literal statements; numeric
// pragma values are formatted with %d from validated integers (the same
// pattern migrate uses for user_version) — configuration input never
// becomes SQL text.
func configure(ctx context.Context, database *sql.DB, opts *Options) error {
	journalStmt, err := journalModePragma(opts.JournalMode)
	if err != nil {
		return err
	}
	synchronousStmt, err := synchronousPragma(opts.Synchronous)
	if err != nil {
		return err
	}
	tempStoreStmt, err := tempStorePragma(opts.TempStore)
	if err != nil {
		return err
	}

	// Pragmas that return a result row are queried and consumed; the rest
	// are executed.
	var mode string
	if err := database.QueryRowContext(ctx, journalStmt).Scan(&mode); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, synchronousStmt); err != nil {
		return err
	}
	// Negative cache_size is kibibytes (the Node agent's MB→negative-KB
	// conversion).
	if _, err := database.ExecContext(ctx,
		fmt.Sprintf("PRAGMA cache_size = %d", -opts.CacheSizeMB*1024)); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, tempStoreStmt); err != nil {
		return err
	}
	var mmap int64
	if err := database.QueryRowContext(ctx,
		fmt.Sprintf("PRAGMA mmap_size = %d", opts.MmapSizeMB*1024*1024)).Scan(&mmap); err != nil {
		return err
	}
	var timeout int
	if err := database.QueryRowContext(ctx,
		fmt.Sprintf("PRAGMA busy_timeout = %d", opts.BusyTimeoutMS)).Scan(&timeout); err != nil {
		return err
	}
	var checkpoint int
	if err := database.QueryRowContext(ctx,
		fmt.Sprintf("PRAGMA wal_autocheckpoint = %d", opts.WALAutocheckpoint)).Scan(&checkpoint); err != nil {
		return err
	}
	if _, err := database.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return err
	}
	if opts.Optimize {
		if _, err := database.ExecContext(ctx, "PRAGMA optimize"); err != nil {
			return err
		}
	}
	return nil
}

// migrate applies the not-yet-applied tail of migrations inside transactions,
// bumping user_version after each script so a failure never half-applies.
func migrate(ctx context.Context, database *sql.DB, migrations []string) error {
	var current int
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return err
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this build understands (%d)",
			current, len(migrations))
	}

	for i := current; i < len(migrations); i++ {
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		// PRAGMA does not accept placeholders; the value is a loop index, not
		// external input.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: set user_version: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %d: commit: %w", i+1, err)
		}
	}
	return nil
}
