// Package config loads and provides the agent's YAML configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// ServerConfig controls the HTTP and HTTPS listeners.
type ServerConfig struct {
	BindAddress string `yaml:"bind_address" json:"bind_address"`
	Port        int    `yaml:"port"         json:"port"`
	// HTTPSPort is the TLS listener's port (the Node agent's
	// server.https_port); bound only when ssl.enabled.
	HTTPSPort int `yaml:"https_port" json:"https_port"`
}

// SSLConfig controls the agent's HTTPS listener (the Node agent's ssl block,
// lib/SSLManager.js semantics: certificate problems never stop the agent —
// HTTPS is skipped with an error in the log and HTTP keeps serving).
type SSLConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// ForceSecure (default true) makes the plain-HTTP port serve ONLY 308
	// redirects once the TLS listener is up — SSL enabled means ALL traffic
	// rides TLS. false is the escape valve (a runtime serving-mode toggle,
	// cors.allow_all's species): the HTTP port keeps serving the full app
	// alongside HTTPS for clients that cannot chase redirects.
	ForceSecure bool `yaml:"force_secure" json:"force_secure"`
	// GenerateSSL creates the server certificate at the paths below when
	// none exists (the Node agent's generateSSLCertificatesIfNeeded, done
	// with crypto/x509 instead of shelling out to openssl). When an
	// operator-provided CA pair exists at the CA paths, the generated server
	// certificate is signed by that CA (Mark's model: ship a CA — wildcard
	// capable — and everything chains to it); otherwise it is self-signed.
	GenerateSSL bool `yaml:"generate_ssl" json:"generate_ssl"`
	// KeyPath/CertPath locate the server private key and certificate. Empty
	// selects <config dir>/ssl/server.key and <config dir>/ssl/server.crt.
	KeyPath  string `yaml:"key_path"  json:"key_path"`
	CertPath string `yaml:"cert_path" json:"cert_path"`
	// CACertPath/CAKeyPath locate the operator-provided CA used to sign the
	// generated server certificate. Empty selects <config dir>/ssl/ca.crt
	// and <config dir>/ssl/ca.key. Absent files mean self-signed generation.
	CACertPath string `yaml:"ca_cert_path" json:"ca_cert_path"`
	CAKeyPath  string `yaml:"ca_key_path"  json:"ca_key_path"`
}

// CORSConfig controls Cross-Origin Resource Sharing (the Node agent's cors
// block): this is an API-key-authenticated backend in a many-to-many mesh —
// the key, not the browser Origin, is the access boundary, so allow_all
// defaults to true. allow_all: false falls back to the explicit whitelist.
type CORSConfig struct {
	AllowAll  bool     `yaml:"allow_all" json:"allow_all"`
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
}

// StatsConfig controls the /stats endpoint (the Node agent's stats block).
type StatsConfig struct {
	// PublicAccess serves GET /stats without an API key.
	PublicAccess bool `yaml:"public_access" json:"public_access"`
}

// CleanupConfig controls the periodic cleanup service (the Node agent's
// cleanup block — its CleanupService cadence; task retention runs on it).
type CleanupConfig struct {
	// Interval is seconds between cleanup runs.
	Interval int `yaml:"interval" json:"interval"`
}

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

// UIConfig controls serving of the embedded Hyperweaver UI.
type UIConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Path optionally serves the UI from a directory on disk instead of the
	// artifact embedded in the binary (dev override, mirrors the Node agent).
	Path string `yaml:"path" json:"path"`
}

// BrowserConfig controls how the tray "Open" action launches a browser.
type BrowserConfig struct {
	// Path is an optional browser executable (or macOS .app bundle). Empty
	// means the operating system's default browser.
	Path string `yaml:"path" json:"path"`
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

// APIKeysConfig controls API-key authentication (Agent API v1 local tier).
// Field names and defaults mirror the Node agent's api_keys block.
type APIKeysConfig struct {
	BootstrapEnabled           bool `yaml:"bootstrap_enabled"             json:"bootstrap_enabled"`
	BootstrapAutoDisable       bool `yaml:"bootstrap_auto_disable"        json:"bootstrap_auto_disable"`
	BootstrapRequireClaimToken bool `yaml:"bootstrap_require_claim_token" json:"bootstrap_require_claim_token"`
	HashRounds                 int  `yaml:"hash_rounds"                   json:"hash_rounds"`
	KeyLength                  int  `yaml:"key_length"                    json:"key_length"`
}

// UpdatesConfig controls update checking (SHI/Node-agent versioninfo model).
type UpdatesConfig struct {
	// VersionInfoURL points at a JSON document {version, releaseUrl,
	// releaseDate, changelog}; empty disables update checking.
	VersionInfoURL string `yaml:"versioninfo_url" json:"versioninfo_url"`
}

// APIDocsConfig controls the interactive Agent API documentation (Swagger UI
// at /api-docs), mirroring the Node agent's api_docs block.
type APIDocsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
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

// TaskOutputConfig controls task output buffering and persistence (the Node
// agent's provisioning.task_output block).
type TaskOutputConfig struct {
	Enabled              bool   `yaml:"enabled"                json:"enabled"`
	Mode                 string `yaml:"mode"                   json:"mode"`
	CircularMaxLines     int    `yaml:"circular_max_lines"     json:"circular_max_lines"`
	FlushIntervalSeconds int    `yaml:"flush_interval_seconds" json:"flush_interval_seconds"`
	PersistLogFile       bool   `yaml:"persist_log_file"       json:"persist_log_file"`
	// LogDirectory receives per-task log files; empty means
	// <config dir>/logs/tasks.
	LogDirectory string `yaml:"log_directory" json:"log_directory"`
}

// TasksConfig controls the task queue (the Node agent's zones.* task knobs +
// provisioning.task_output, regrouped under one section).
type TasksConfig struct {
	// PollIntervalSeconds is the queue tick (the Node agent hardcodes 2).
	PollIntervalSeconds int `yaml:"poll_interval_seconds" json:"poll_interval_seconds"`
	// MaxConcurrent caps simultaneously running tasks (Node:
	// zones.max_concurrent_tasks).
	MaxConcurrent int `yaml:"max_concurrent" json:"max_concurrent"`
	// DefaultPaginationLimit is GET /tasks' default limit (Node:
	// zones.default_pagination_limit).
	DefaultPaginationLimit int `yaml:"default_pagination_limit" json:"default_pagination_limit"`
	// RetentionDays: finished tasks older than this are deleted by the
	// periodic cleanup (Node: host_monitoring.retention.tasks).
	RetentionDays int              `yaml:"retention_days" json:"retention_days"`
	Output        TaskOutputConfig `yaml:"output"         json:"output"`
}

// MonitoringConfig controls the host telemetry surface (/monitoring/*, the
// `monitoring` capability token — the Node agent's host_monitoring block,
// reshaped per Mark's 2026-07-05 ruling): the endpoints always serve REALTIME
// samples; enabling storage adds a background collector writing time series
// into per-datatype database files (monitoring-cpu.sqlite,
// monitoring-memory.sqlite, monitoring-network.sqlite) so telemetry write
// churn never contends with the main databases — the single-file IO
// contention zoneweaver hits.
type MonitoringConfig struct {
	// StorageEnabled turns the background collector on. Off (default) means
	// realtime-only: every request samples the OS live, history queries
	// return just the current sample.
	StorageEnabled bool `yaml:"storage_enabled" json:"storage_enabled"`
	// CollectionInterval is seconds between collector samples.
	CollectionInterval int `yaml:"collection_interval" json:"collection_interval"`
	// RetentionDays: stored samples older than this are deleted by the
	// periodic cleanup.
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
}

// HostPowerConfig gates the host power-management surface (/system/host/*,
// the `host-power` capability token): remote shutdown/restart of the machine
// the agent runs on — half the point of a headless datacenter host, an
// obvious kill-switch candidate on a desktop.
type HostPowerConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// MachinesConfig controls the machine registry (the Node agent's zones.*
// discovery knobs).
type MachinesConfig struct {
	// AutoDiscovery enables the periodic discover tasks (Node:
	// zones.auto_discovery). The startup discovery task always runs.
	AutoDiscovery bool `yaml:"auto_discovery" json:"auto_discovery"`
	// DiscoveryInterval is seconds between periodic discover tasks (Node:
	// zones.discovery_interval). Discovery reconciles the registry against
	// VirtualBox and vagrant — external-shutdown detection included.
	DiscoveryInterval int `yaml:"discovery_interval" json:"discovery_interval"`
	// ServerIDStart is the lowest auto-assigned server_id (Node:
	// zones.server_id_start).
	ServerIDStart int `yaml:"server_id_start" json:"server_id_start"`
	// PrefixMachineNames derives created machines' names as
	// <server_id>--<hostname>.<domain> when no explicit name is given
	// (zoneweaver's prefix_zone_names — Mark's partition-id convention).
	// Explicit names always win: machine names stay free-form (design D-G).
	PrefixMachineNames bool `yaml:"prefix_machine_names" json:"prefix_machine_names"`
	// ShutdownTimeout is how many seconds a graceful stop waits for the
	// guest to power off after the ACPI signal before forcing poweroff
	// (Node: zones.orchestration.timeouts.zone_shutdown).
	ShutdownTimeout int `yaml:"shutdown_timeout" json:"shutdown_timeout"`
	// KeepRunningOnExit keeps provisioned machines running when the agent
	// exits (SHI's keepserversrunning, default true). false force-powers-off
	// every spec-carrying machine at shutdown — machines discovered from
	// VirtualBox are never touched.
	KeepRunningOnExit bool `yaml:"keep_running_on_exit" json:"keep_running_on_exit"`
}

// ProvisioningSSHConfig controls the pipeline's SSH access to guests (the
// base's provisioning.ssh block).
type ProvisioningSSHConfig struct {
	// KeyPath is the agent's own provisioning private key (generated at
	// startup when absent — ed25519). Empty selects ssh/provision_key beside
	// the configuration file.
	KeyPath string `yaml:"key_path" json:"key_path"`
	// TimeoutSeconds bounds the total wait for a guest's SSH to answer.
	TimeoutSeconds int `yaml:"timeout_seconds" json:"timeout_seconds"`
	// PollIntervalSeconds is the wait between SSH availability checks.
	PollIntervalSeconds int `yaml:"poll_interval_seconds" json:"poll_interval_seconds"`
}

// ProvisioningConfig controls the provisioning engine (architecture §8, the
// zoneweaver mechanism): the package registry, per-machine working
// directories, and the SSH/ansible pipeline knobs.
type ProvisioningConfig struct {
	// ProvisionersDir holds provisioner packages in SHI's on-disk format
	// (<name>/provisioner-collection.yml with <version>/provisioner.yml
	// trees beneath). Installer-bundled packages are extracted here on
	// startup without ever overwriting existing versions. Empty selects
	// provisioners under the data root.
	ProvisionersDir string `yaml:"provisioners_dir" json:"provisioners_dir"`
	// DefaultSyncMethod is the sync method machines without an explicit
	// spec.sync_method use (rsync | scp; SHI's global syncmethod preference).
	// Platform rules still apply on top.
	DefaultSyncMethod string `yaml:"default_sync_method" json:"default_sync_method"`
	// DefaultNetworkInterface names the host bridge interface injected into
	// the template context (DEFAULT_NETWORK_INTERFACE) when the spec sets
	// none — SHI's defaultNetworkInterface fallback, fed by
	// `VBoxManage list bridgedifs`.
	DefaultNetworkInterface string `yaml:"default_network_interface" json:"default_network_interface"`
	// MachinesDir holds the per-machine working directories: the
	// materialized provisioner copy, the rendered Hosts.yml, id-files,
	// installers, ssls trees, and the machine's media. Empty selects
	// machines under the data root.
	MachinesDir string `yaml:"machines_dir" json:"machines_dir"`
	// PlaybookTimeoutSeconds bounds one ansible-playbook run in the guest.
	PlaybookTimeoutSeconds int `yaml:"playbook_timeout_seconds" json:"playbook_timeout_seconds"`
	// AnsibleInstallTimeoutSeconds bounds the in-guest ansible/collection
	// installation steps.
	AnsibleInstallTimeoutSeconds int `yaml:"ansible_install_timeout_seconds" json:"ansible_install_timeout_seconds"`
	// SSH is the pipeline's guest-access configuration.
	SSH ProvisioningSSHConfig `yaml:"ssh" json:"ssh"`
}

// TemplateSourceConfig is one configured box registry
// (Vagrant/BoxVault-compatible download API).
type TemplateSourceConfig struct {
	Name    string `yaml:"name"    json:"name"`
	URL     string `yaml:"url"     json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Default bool   `yaml:"default" json:"default"`
	// AuthToken authenticates private boxes (Bearer); a per-request
	// auth token overrides it.
	AuthToken string `yaml:"auth_token" json:"auth_token"`
}

// TemplateSourcesConfig controls the box-template registry (the base's
// template_sources block): where downloaded box disk images live and which
// registries serve them.
type TemplateSourcesConfig struct {
	// LocalStoragePath is the template storage root
	// (<root>/<org>/<box>/<version>/). Empty selects templates under the
	// data root.
	LocalStoragePath string `yaml:"local_storage_path" json:"local_storage_path"`
	// Sources are the configured registries; the entry named "Default
	// Registry" (or flagged default) serves requests that name no source.
	Sources []TemplateSourceConfig `yaml:"sources" json:"sources"`
}

// AssetsConfig controls the installer file cache (the `artifacts` capability
// token — SHI's file cache with hash verification, implemented in full per
// Mark's 2026-07-06 ruling).
type AssetsConfig struct {
	// Enabled serves the /artifacts surface and enforces cache verification
	// at machine prepare time. Disabled, installer references pass through
	// un-mounted with a loud warning.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Dir is the cache root (SHI layout:
	// <dir>/<role>/{installers,fixpacks,hotfixes}/<file>). Empty selects
	// file-cache under the data root.
	Dir string `yaml:"dir" json:"dir"`
	// MaxUploadGB caps one artifact upload's size.
	MaxUploadGB int `yaml:"max_upload_gb" json:"max_upload_gb"`
}

// Config is the root of config.yaml.
type Config struct {
	Server          ServerConfig          `yaml:"server"           json:"server"`
	SSL             SSLConfig             `yaml:"ssl"              json:"ssl"`
	CORS            CORSConfig            `yaml:"cors"             json:"cors"`
	UI              UIConfig              `yaml:"ui"               json:"ui"`
	Browser         BrowserConfig         `yaml:"browser"          json:"browser"`
	Logging         LoggingConfig         `yaml:"logging"          json:"logging"`
	APIKeys         APIKeysConfig         `yaml:"api_keys"         json:"api_keys"`
	Updates         UpdatesConfig         `yaml:"updates"          json:"updates"`
	APIDocs         APIDocsConfig         `yaml:"api_docs"         json:"api_docs"`
	Stats           StatsConfig           `yaml:"stats"            json:"stats"`
	Data            DataConfig            `yaml:"data"             json:"data"`
	Database        DatabaseConfig        `yaml:"database"         json:"database"`
	Tasks           TasksConfig           `yaml:"tasks"            json:"tasks"`
	Machines        MachinesConfig        `yaml:"machines"         json:"machines"`
	Provisioning    ProvisioningConfig    `yaml:"provisioning"     json:"provisioning"`
	TemplateSources TemplateSourcesConfig `yaml:"template_sources" json:"template_sources"`
	Assets          AssetsConfig          `yaml:"assets"           json:"assets"`
	Cleanup         CleanupConfig         `yaml:"cleanup"          json:"cleanup"`
	Monitoring      MonitoringConfig      `yaml:"monitoring"       json:"monitoring"`
	HostPower       HostPowerConfig       `yaml:"host_power"       json:"host_power"`

	// path is where this configuration was loaded from; the setup token, key
	// store, protocol-handoff secret, and config backups live beside it.
	path string
}

// Default returns the built-in configuration values.
func Default() *Config {
	return &Config{
		Server:  ServerConfig{BindAddress: "127.0.0.1", Port: 9420, HTTPSPort: 9421},
		SSL:     SSLConfig{Enabled: true, ForceSecure: true, GenerateSSL: true},
		CORS:    CORSConfig{AllowAll: true, Whitelist: []string{}},
		UI:      UIConfig{Enabled: true},
		Browser: BrowserConfig{},
		Logging: LoggingConfig{
			Level:       "info",
			Console:     true,
			MaxSizeMB:   20,
			MaxBackups:  5,
			Compression: true,
			Categories:  map[string]string{},
		},
		APIKeys: APIKeysConfig{
			BootstrapEnabled:           true,
			BootstrapAutoDisable:       true,
			BootstrapRequireClaimToken: true,
			HashRounds:                 12,
			KeyLength:                  64,
		},
		Updates: UpdatesConfig{
			VersionInfoURL: "https://github.com/Makr91/hyperweaver-agent/releases/latest/download/update-info.json",
		},
		APIDocs: APIDocsConfig{Enabled: true},
		Stats:   StatsConfig{PublicAccess: false},
		Data:    DataConfig{},
		Database: DatabaseConfig{
			SQLiteOptions: SQLiteOptionsConfig{
				JournalMode:       "WAL",
				Synchronous:       "NORMAL",
				CacheSizeMB:       128,
				TempStore:         "MEMORY",
				MmapSizeMB:        512,
				BusyTimeoutMS:     30000,
				WALAutocheckpoint: 1000,
				Optimize:          true,
			},
		},
		Tasks: TasksConfig{
			PollIntervalSeconds:    2,
			MaxConcurrent:          5,
			DefaultPaginationLimit: 50,
			RetentionDays:          30,
			Output: TaskOutputConfig{
				Enabled:              true,
				Mode:                 "full",
				CircularMaxLines:     10000,
				FlushIntervalSeconds: 10,
				PersistLogFile:       true,
			},
		},
		Machines: MachinesConfig{
			AutoDiscovery:      true,
			DiscoveryInterval:  300,
			ServerIDStart:      1,
			PrefixMachineNames: false,
			ShutdownTimeout:    120,
			KeepRunningOnExit:  true,
		},
		Provisioning: ProvisioningConfig{
			DefaultSyncMethod:            "rsync",
			PlaybookTimeoutSeconds:       21600,
			AnsibleInstallTimeoutSeconds: 300,
			SSH: ProvisioningSSHConfig{
				TimeoutSeconds:      300,
				PollIntervalSeconds: 10,
			},
		},
		TemplateSources: TemplateSourcesConfig{
			Sources: []TemplateSourceConfig{{
				Name:    "Default Registry",
				URL:     "https://boxvault.startcloud.com",
				Enabled: true,
				Default: true,
			}},
		},
		Assets:  AssetsConfig{Enabled: true, MaxUploadGB: 50},
		Cleanup: CleanupConfig{Interval: 300},
		Monitoring: MonitoringConfig{
			StorageEnabled:     false,
			CollectionInterval: 60,
			RetentionDays:      7,
		},
		HostPower: HostPowerConfig{Enabled: true},
	}
}

// Dir returns the agent's per-user configuration directory
// (%AppData%\hyperweaver-agent on Windows, ~/Library/Application
// Support/hyperweaver-agent on macOS, XDG config dir on Linux).
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(base, "hyperweaver-agent"), nil
}

// DefaultPath returns the default config.yaml location.
func DefaultPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// Load reads the configuration from path. When path is empty the per-user
// default location is used, and a commented default file is created there on
// first run. The resolved path is returned alongside the config.
func Load(path string) (*Config, string, error) {
	resolved := path
	if resolved == "" {
		defaultPath, err := DefaultPath()
		if err != nil {
			return nil, "", err
		}
		resolved = defaultPath
	}

	// Sanitize before any filesystem access; everything derived from the
	// config location (key store, setup token, backups) inherits this.
	resolved, err := safepath.CleanAbs(resolved)
	if err != nil {
		return nil, "", err
	}

	if path == "" {
		if derr := ensureDefaultFile(resolved); derr != nil {
			return nil, "", derr
		}
	}

	data, err := os.ReadFile(filepath.Clean(resolved))
	if err != nil {
		return nil, "", fmt.Errorf("read config %s: %w", resolved, err)
	}

	cfg := Default()
	if err := yaml.UnmarshalWithOptions(data, cfg, yaml.Strict()); err != nil {
		return nil, "", fmt.Errorf("parse config %s: %w", resolved, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, "", fmt.Errorf("invalid config %s: %w", resolved, err)
	}
	cfg.path = resolved
	return cfg, resolved, nil
}

// ListenAddr returns the host:port the HTTP server binds to.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.BindAddress, strconv.Itoa(c.Server.Port))
}

// HTTPSListenAddr returns the host:port the HTTPS server binds to.
func (c *Config) HTTPSListenAddr() string {
	return net.JoinHostPort(c.Server.BindAddress, strconv.Itoa(c.Server.HTTPSPort))
}

// BaseURL returns the agent's locally reachable origin. With ssl.enabled the
// origin is the HTTPS one — Mark's ruling (2026-07-05): SSL enabled means ALL
// traffic rides TLS (the plain listener only redirects), a deliberate
// divergence from the Node agent's serve-both model. A wildcard bind address
// is rewritten to a loopback address the local machine can reach.
func (c *Config) BaseURL() string {
	host := c.Server.BindAddress
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if c.SSL.Enabled {
		return "https://" + net.JoinHostPort(host, strconv.Itoa(c.Server.HTTPSPort))
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(c.Server.Port))
}

// LocalURL returns the URL the tray "Open" action launches.
func (c *Config) LocalURL() string {
	return c.BaseURL() + "/ui/"
}
