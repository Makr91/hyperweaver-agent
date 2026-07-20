// Package config loads and provides the agent's YAML configuration.
package config

// SQLiteOptionsConfig tunes the SQLite session pragmas applied to both agent
// databases (the Node agent's database.sqlite_options). Its pool and retry
// sub-blocks are deliberately not ported: this agent runs one pooled
// connection per database (single-writer by construction — no busy retries
// between its own goroutines to configure).
type SQLiteOptionsConfig struct {
	JournalMode       string `yaml:"journal_mode"       json:"journal_mode"`
	Synchronous       string `yaml:"synchronous"        json:"synchronous"`
	CacheSizeMB       int    `yaml:"cache_size_mb"      json:"cache_size_mb"`
	TempStore         string `yaml:"temp_store"         json:"temp_store"`
	MmapSizeMB        int    `yaml:"mmap_size_mb"       json:"mmap_size_mb"`
	BusyTimeoutMS     int    `yaml:"busy_timeout_ms"    json:"busy_timeout_ms"`
	WALAutocheckpoint int    `yaml:"wal_autocheckpoint" json:"wal_autocheckpoint"`
	Optimize          bool   `yaml:"optimize"           json:"optimize"`
}

// DatabaseConfig groups database tuning. Dialect and storage paths are not
// configuration on this agent: SQLite is the only engine and the files live
// under data.dir (architecture D-A).
type DatabaseConfig struct {
	SQLiteOptions SQLiteOptionsConfig `yaml:"sqlite_options" json:"sqlite_options"`
}
