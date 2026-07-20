// Package config loads and provides the agent's YAML configuration.
package config

// ArtifactPathConfig is one artifact_storage.paths[] entry — an
// operator-added storage location (zoneweaver's paths[] shape).
type ArtifactPathConfig struct {
	Name    string `yaml:"name"    json:"name"`
	Path    string `yaml:"path"    json:"path"`
	Type    string `yaml:"type"    json:"type"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

// ArtifactDownloadConfig tunes URL downloads (zoneweaver's download block;
// progress cadence is informational — the executor reports about once per
// second regardless).
type ArtifactDownloadConfig struct {
	TimeoutSeconds int `yaml:"timeout_seconds" json:"timeout_seconds"`
}

// ArtifactScanningConfig tunes location scans.
type ArtifactScanningConfig struct {
	// PeriodicScanInterval is seconds between automatic direct scans
	// (0 disables; startup always scans once).
	PeriodicScanInterval int `yaml:"periodic_scan_interval" json:"periodic_scan_interval"`
	// SupportedExtensions filter iso/image scans per type. Empty selects the
	// defaults (iso: .iso; image: .vmdk .raw .vdi .qcow2 .img .ova .ovf).
	SupportedExtensions map[string][]string `yaml:"supported_extensions" json:"supported_extensions"`
}

// ArtifactStorageConfig controls the merged artifact system (the `artifacts`
// capability token — Mark's ruling 2026-07-09: ONE zoneweaver-shaped system
// where iso, image, installer, fixpack, and hotfix are all location types,
// with SHI's hash verification in full).
type ArtifactStorageConfig struct {
	// Enabled serves the /artifacts surface and enforces cache verification
	// at machine prepare time. Disabled, installer references pass through
	// un-mounted with a loud warning.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Dir hosts the built-in locations (<dir>/isos, images, installers,
	// fixpacks, hotfixes). Empty selects artifacts under the data root.
	Dir string `yaml:"dir" json:"dir"`
	// MaxUploadGB caps one artifact upload's size.
	MaxUploadGB int                    `yaml:"max_upload_gb" json:"max_upload_gb"`
	Download    ArtifactDownloadConfig `yaml:"download"      json:"download"`
	Scanning    ArtifactScanningConfig `yaml:"scanning"      json:"scanning"`
	// Paths are additional storage locations beyond the built-ins; the API's
	// storage-path CRUD persists here.
	Paths []ArtifactPathConfig `yaml:"paths" json:"paths"`
}
