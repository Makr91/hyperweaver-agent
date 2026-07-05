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

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Open opens (creating if needed) the SQLite database at path and applies
// migrations. Each migration is one SQL script; user_version records how many
// have been applied, so a database created by an older build is upgraded by
// running only the scripts it has not seen.
func Open(ctx context.Context, path string, migrations []string) (*sql.DB, error) {
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

	if err := configure(ctx, database); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("configure database %s: %w", clean, err)
	}
	if err := migrate(ctx, database, migrations); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("migrate database %s: %w", clean, err)
	}
	return database, nil
}

// configure applies the session pragmas: WAL journaling (readers never block
// the writer), a busy timeout as a second line of defense, and enforced
// foreign keys.
func configure(ctx context.Context, database *sql.DB) error {
	// journal_mode and busy_timeout return a result row — consume it.
	var mode string
	if err := database.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return err
	}
	var timeout int
	if err := database.QueryRowContext(ctx, "PRAGMA busy_timeout=5000").Scan(&timeout); err != nil {
		return err
	}
	_, err := database.ExecContext(ctx, "PRAGMA foreign_keys=ON")
	return err
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
