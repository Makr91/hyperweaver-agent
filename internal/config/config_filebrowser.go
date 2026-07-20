// Package config loads and provides the agent's YAML configuration.
package config

// FileBrowserSecurityConfig bounds the file browser (zoneweaver's
// file_browser.security block).
type FileBrowserSecurityConfig struct {
	// PreventTraversal rejects paths carrying ".." or "~".
	PreventTraversal bool `yaml:"prevent_traversal" json:"prevent_traversal"`
	// MaxDirectoryEntries refuses listing directories larger than this.
	MaxDirectoryEntries int `yaml:"max_directory_entries" json:"max_directory_entries"`
	// MaxEditSizeMB caps files the content read/write endpoints handle (the
	// text-editor path; download/upload stream without this bound).
	MaxEditSizeMB int `yaml:"max_edit_size_mb" json:"max_edit_size_mb"`
	// ForbiddenPaths rejects any path underneath these prefixes.
	ForbiddenPaths []string `yaml:"forbidden_paths" json:"forbidden_paths"`
	// ForbiddenPatterns rejects paths matching these glob-style patterns
	// (* matches anything).
	ForbiddenPatterns []string `yaml:"forbidden_patterns" json:"forbidden_patterns"`
}

// FileBrowserArchiveConfig gates the archive operations (zoneweaver's
// file_browser.archive block). Creation formats this agent speaks natively:
// zip, tar, tar.gz (Go's bzip2 is decompress-only — tar.bz2 EXTRACTS fine but
// cannot be created here, an honest platform divergence from the base's shell
// tar).
type FileBrowserArchiveConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// SupportedFormats limits what POST /filesystem/archive/create accepts.
	SupportedFormats []string `yaml:"supported_formats" json:"supported_formats"`
	// MaxArchiveSizeMB deletes a created archive that lands larger than this.
	MaxArchiveSizeMB int `yaml:"max_archive_size_mb" json:"max_archive_size_mb"`
}

// FileBrowserConfig gates the host file-browser surface (/filesystem, the
// `file-browser` capability token — zoneweaver's file_browser block: browse
// plus the full mutate/archive family, Mark's 1:1 ruling 2026-07-12).
type FileBrowserConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Root confines browsing to one directory: "/" maps here and paths
	// outside answer 403. Empty means unrestricted — "/" lists the host's
	// drive letters on Windows and the real root elsewhere. (The base never
	// needed this: its "/" IS the illumos root.)
	Root string `yaml:"root" json:"root"`
	// UploadSizeLimitGB caps one POST /filesystem/upload body.
	UploadSizeLimitGB int                       `yaml:"upload_size_limit_gb" json:"upload_size_limit_gb"`
	Security          FileBrowserSecurityConfig `yaml:"security" json:"security"`
	Archive           FileBrowserArchiveConfig  `yaml:"archive"  json:"archive"`
}
