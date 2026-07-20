package assets

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
