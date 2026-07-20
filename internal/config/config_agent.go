// Package config loads and provides the agent's YAML configuration.
package config

// UIConfig controls serving of the embedded Hyperweaver UI.
type UIConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Path optionally serves the UI from a directory on disk instead of the
	// artifact embedded in the binary (dev override, mirrors the Node agent).
	Path string `yaml:"path" json:"path"`
	// SHIMode turns on the "I Can't Believe it's not Super.Human.Installer"
	// presentation (Mark's ruling 2026-07-07): the agent just carries and
	// advertises the flag (shi_mode on GET /api/status); the SPA renders the
	// opinionated SHI-style theme/flow from it in Direct mode.
	SHIMode bool `yaml:"shi_mode" json:"shi_mode"`
}

// StartupConfig controls how the agent itself starts (the desktop login
// story; headless installs boot via their service manager).
type StartupConfig struct {
	// StartAtLogin registers the agent with the OS's native login-item
	// mechanism (HKCU Run key / LaunchAgent plist / XDG autostart entry).
	// Converged at every boot: false removes the registration.
	StartAtLogin bool `yaml:"start_at_login" json:"start_at_login"`
}

// BrowserConfig controls how the agent launches a browser (the tray "Open"
// action and the startup open).
type BrowserConfig struct {
	// Path is an optional browser executable (or macOS .app bundle). Empty
	// means the operating system's default browser.
	Path string `yaml:"path" json:"path"`
	// OpenOnStart opens the signed-in UI in the browser when the desktop
	// agent starts (Mark's ruling 2026-07-07: one less click — a fresh
	// install lands in the browser instead of a tray hunt). Headless mode
	// ignores it.
	OpenOnStart bool `yaml:"open_on_start" json:"open_on_start"`
}

// LoggingConfig controls slog output.
type LoggingConfig struct {
	Level      string `yaml:"level"       json:"level"`
	Console    bool   `yaml:"console"     json:"console"`
	File       string `yaml:"file"        json:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb" json:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups" json:"max_backups"`
	// Compression gzips rotated log files (the Node agent's
	// logging.enable_compression; lumberjack compresses at rotation time, so
	// its compression_age_days delay has no analog here).
	Compression bool `yaml:"compression" json:"compression"`
	// Categories overrides the level per log category (the Node agent's
	// logging.categories / per-category winston loggers). Categories this
	// agent emits: app (the default), api_requests, auth, tasks, machines,
	// monitoring, provisioning, assets.
	Categories map[string]string `yaml:"categories" json:"categories"`
}

// DataConfig locates the agent's data root — SQLite databases today; machine
// working directories, provisioners, and the file cache in later phases.
// Distinct from the config directory: on Windows the config lives in the
// Roaming profile, and VM-scale data must not sync with it.
type DataConfig struct {
	// Dir is the data root. Empty selects the per-OS local-appdata default
	// (see DataDir).
	Dir string `yaml:"dir" json:"dir"`
}

// CleanupConfig controls the periodic cleanup service (the Node agent's
// cleanup block — its CleanupService cadence; task retention runs on it).
type CleanupConfig struct {
	// Interval is seconds between cleanup runs.
	Interval int `yaml:"interval" json:"interval"`
}

// ApplicationConfig is one external application the agent can launch on its
// own desktop against a machine (Mark's go 2026-07-12 — the Direct-mode
// launcher registry: open-in-PuTTY/WinSCP-style actions). Args entries may
// carry the placeholders {host}, {port}, {user}, {password} — resolved per
// machine through the SSH transport ladder and stored credentials — and
// {machine} (the machine name).
type ApplicationConfig struct {
	Name string   `yaml:"name" json:"name"`
	Path string   `yaml:"path" json:"path"`
	Args []string `yaml:"args" json:"args"`
}

// TicketSystemConfig feeds the UI's Help & Support link (the profile
// dropdown; BoxVault's ticket_system pattern). Served publicly at
// GET /api/config/ticket in the {value}-wrapped shape the UI consumes; the
// link renders only when enabled AND base_url is set.
type TicketSystemConfig struct {
	Enabled bool   `yaml:"enabled"  json:"enabled"`
	BaseURL string `yaml:"base_url" json:"base_url"`
	ReqType string `yaml:"req_type" json:"req_type"`
	Context string `yaml:"context"  json:"context"`
}
