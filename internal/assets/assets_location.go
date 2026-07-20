package assets

import "time"

// Location is one typed storage location (zoneweaver's
// artifact_storage_locations shape). source builtin = the five
// always-present locations under artifact_storage.dir (never deletable —
// disable instead); source config = artifact_storage.paths[] entries, which
// the storage-path API also creates and persists back into config.yaml.
type Location struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Path       string     `json:"path"`
	Type       string     `json:"type"`
	Enabled    bool       `json:"enabled"`
	Source     string     `json:"source"`
	ConfigHash string     `json:"config_hash,omitempty"`
	FileCount  int64      `json:"file_count"`
	TotalSize  int64      `json:"total_size"`
	LastScanAt *time.Time `json:"last_scan_at"`
	// Consecutive scan failures
	ScanErrors int       `json:"scan_errors"`
	LastError  string    `json:"last_error_message,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
