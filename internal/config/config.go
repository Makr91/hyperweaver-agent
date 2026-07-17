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
	RetentionDays int `yaml:"retention_days" json:"retention_days"`
	// ResumePendingOnStart keeps pending tasks across an agent restart (the
	// resumable queue). Default false: pending rows from a previous run are
	// CANCELLED at boot — the base's startup clear (Mark's ruling 2026-07-07:
	// yesterday's queued stop must never fire on today's start).
	ResumePendingOnStart bool             `yaml:"resume_pending_on_start" json:"resume_pending_on_start"`
	Output               TaskOutputConfig `yaml:"output"                  json:"output"`
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
	// PreventSleep keeps the host awake while the agent runs (SHI's
	// preventsystemfromsleep, default false) using each OS's native
	// power-management API — SetThreadExecutionState / IOKit power assertion /
	// systemd-logind inhibitor. System sleep only; the display may still
	// sleep and lock.
	PreventSleep bool `yaml:"prevent_sleep" json:"prevent_sleep"`
}

// ResourceThresholdsConfig are the warn/critical utilization percentages a
// validator annotates (warnings never block; the hard checks do).
type ResourceThresholdsConfig struct {
	Warning  float64 `yaml:"warning"  json:"warning"`
	Critical float64 `yaml:"critical" json:"critical"`
}

// ResourceCheckConfig is one validator's knobs (the base's
// zones.resource_validation.storage/memory blocks). Strategy: "committed"
// projects against the sum of every machine's CONFIGURED allocation;
// "actual" checks against the host's current free amount.
type ResourceCheckConfig struct {
	Enabled    bool                     `yaml:"enabled"    json:"enabled"`
	Strategy   string                   `yaml:"strategy"   json:"strategy"`
	Thresholds ResourceThresholdsConfig `yaml:"thresholds" json:"thresholds"`
}

// CPUValidationConfig adds the overcommit hard limit (vCPUs may legitimately
// exceed physical cores — the limit is a percentage of them).
type CPUValidationConfig struct {
	Enabled    bool                     `yaml:"enabled"    json:"enabled"`
	Strategy   string                   `yaml:"strategy"   json:"strategy"`
	HardLimit  float64                  `yaml:"hard_limit" json:"hard_limit"`
	Thresholds ResourceThresholdsConfig `yaml:"thresholds" json:"thresholds"`
}

// ResourceValidationConfig gates the pre-flight resource checks on create,
// clone, and modify (the base's zones.resource_validation, VirtualBox terms:
// disk free where the media land, host RAM, CPU overcommit). Failing checks
// answer 400 {error: "Insufficient resources", details[]}; passing checks may
// still annotate resource_warnings[].
type ResourceValidationConfig struct {
	Enabled bool                `yaml:"enabled" json:"enabled"`
	Storage ResourceCheckConfig `yaml:"storage" json:"storage"`
	Memory  ResourceCheckConfig `yaml:"memory"  json:"memory"`
	CPU     CPUValidationConfig `yaml:"cpu"     json:"cpu"`
}

// OrchestrationConfig controls ordered machine startup/shutdown (the base's
// zones.orchestration): machines carry settings.boot_priority (1-100, default
// 95, the base's zonecfg attr in this agent's spec vocabulary); at agent
// startup, autostart machines boot highest-priority first; at agent exit
// (keep_running_on_exit false) machines stop lowest-first.
type OrchestrationConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Strategy shapes the shutdown/test plan: sequential |
	// parallel_by_priority | staggered.
	Strategy string `yaml:"strategy" json:"strategy"`
	// PriorityDelay is seconds between priority groups (staggered strategy,
	// and the test plan's duration estimate).
	PriorityDelay int `yaml:"priority_delay" json:"priority_delay"`
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
	// ResourceValidation are the pre-flight resource checks on
	// create/clone/modify.
	ResourceValidation ResourceValidationConfig `yaml:"resource_validation" json:"resource_validation"`
	// Orchestration is ordered startup/shutdown by settings.boot_priority.
	Orchestration OrchestrationConfig `yaml:"orchestration" json:"orchestration"`
	// ProvisionOnStart makes a machine's VERY FIRST start (a stored
	// provisioner document, never provisioned) run the full provision
	// pipeline instead of a bare boot — SHI's dormant provisionserversonstart
	// preference, Mark's semantics 2026-07-07. Later starts, document-less
	// machines, restarts, and provision-chain boot children are never
	// affected. Default false.
	ProvisionOnStart bool `yaml:"provision_on_start" json:"provision_on_start"`
}

// ProvisioningNetworkConfig controls the dedicated provisioning network (the
// base's provisioning.network block — etherstub + host VNIC + static IP +
// dhcpd on illumos). VirtualBox collapses that triple into ONE host-only
// interface, identified by host_ip because VirtualBox assigns interface names
// itself; its own DHCP server carries the base's dhcpd role, so the base's
// etherstub_name/host_vnic_name fields have no analog here. The base's
// NAT/forwarding pieces (provisioning-NIC egress) live elsewhere on
// VirtualBox: the provisioning NIC is the NAT adapter pinned at create
// (adapter 1, ssh port-forward transport — Mark's architecture 2026-07-07).
// This host-only machinery stays dormant-but-available for host-type
// networks[] entries and build-it-yourself setups.
type ProvisioningNetworkConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Subnet is the provisioning network in CIDR form.
	Subnet string `yaml:"subnet" json:"subnet"`
	// HostIP is the host's address on the network — the interface identity.
	HostIP string `yaml:"host_ip" json:"host_ip"`
	// Netmask is the network mask.
	Netmask string `yaml:"netmask" json:"netmask"`
	// DHCPServerIP is the VirtualBox DHCP server's OWN address (VirtualBox
	// requires one distinct from the interface's — the base's dhcpd binds the
	// host IP itself, which has no analog here).
	DHCPServerIP string `yaml:"dhcp_server_ip" json:"dhcp_server_ip"`
	// DHCPRangeStart/DHCPRangeEnd bound the assignable pool; fixed leases and
	// the clone allocator draw from it.
	DHCPRangeStart string `yaml:"dhcp_range_start" json:"dhcp_range_start"`
	DHCPRangeEnd   string `yaml:"dhcp_range_end"   json:"dhcp_range_end"`
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
	// HostHooks allows sequence hooks (provisioning.pre[]/post[] in a
	// machine's document) with target: host to run scripts ON THE AGENT HOST
	// (design §5, ruled 2026-07-16 — default ON for this agent; zoneweaver
	// defaults OFF, its hosts are shared). Guest-target hooks are always
	// allowed. Non-seeded packages additionally confirm once per machine.
	HostHooks bool `yaml:"host_hooks" json:"host_hooks"`
	// SSH is the pipeline's guest-access configuration.
	SSH ProvisioningSSHConfig `yaml:"ssh" json:"ssh"`
	// Network is the dedicated provisioning network.
	Network ProvisioningNetworkConfig `yaml:"network" json:"network"`
}

// TemplateSourceConfig is one configured box registry
// (Vagrant/BoxVault-compatible download API).
type TemplateSourceConfig struct {
	Name    string `yaml:"name"    json:"name"`
	URL     string `yaml:"url"     json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Default bool   `yaml:"default" json:"default"`
	// AuthToken is the registry API key — a BoxVault service-account token,
	// sent raw as Bearer on every call (vagrant's own model; Mark's ruling
	// 2026-07-09: "API keys, PERIOD"). The ONLY credential: the base's
	// username/JWT signin ladder is deliberately dead.
	AuthToken string `yaml:"auth_token" json:"auth_token"`
	// CAFile adds a PEM CA bundle to the trust store for this registry —
	// the self-signed-registry answer. Verification always stays on (the
	// base's verify_ssl:false is deliberately not ported).
	CAFile string `yaml:"ca_file" json:"ca_file"`
}

// TemplateSourcesConfig controls the box-template registry (the base's
// template_sources block): where downloaded box disk images live and which
// registries serve them.
type TemplateSourcesConfig struct {
	// LocalStoragePath is the template storage root
	// (<root>/<org>/<box>/<version>/). Empty selects templates under the
	// data root.
	LocalStoragePath string `yaml:"local_storage_path" json:"local_storage_path"`
	// Sources are the configured registries; the entry flagged default
	// serves requests that name no source (names are display-only).
	Sources []TemplateSourceConfig `yaml:"sources" json:"sources"`
}

// CatalogSourceConfig is one configured provisioner catalog (design §7 —
// the HACS model; the second door is a forked catalog repo added here).
type CatalogSourceConfig struct {
	Name    string `yaml:"name"    json:"name"`
	URL     string `yaml:"url"     json:"url"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Default bool   `yaml:"default" json:"default"`
	// CAFile adds a PEM CA bundle to the trust store for this catalog —
	// self-hosted forks behind private CAs. Verification always stays on.
	CAFile string `yaml:"ca_file" json:"ca_file"`
}

// CatalogSourcesConfig controls the provisioner catalog client (mirrors the
// template-sources pattern).
type CatalogSourcesConfig struct {
	Sources []CatalogSourceConfig `yaml:"sources" json:"sources"`
}

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

// GuestAgentConfig gates the QEMU guest-agent channel (the `guest-agent`
// capability token — Mark's go 2026-07-10): the MASTER gate over the
// per-machine UART option (zones.guest_agent at create, the PUT toggle, the
// setup endpoint) and the /machines/{name}/guest/* surface — credential-less
// live IPs, exec, clean shutdown with no SSH and no Guest Additions.
type GuestAgentConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
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

// SnapshotTierConfig is one rotation tier's keep count.
type SnapshotTierConfig struct {
	Keep int `yaml:"keep" json:"keep"`
}

// SnapshotPolicyConfig is one snapshot retention policy — the shared
// vocabulary with zoneweaver (its snapshots.default_policy and the per-zone
// configuration.snapshots override; Mark's ruling 2026-07-12: same shape on
// both agents, VBox-tuned CONSERVATIVE defaults here — VirtualBox snapshot
// creation is CoW-thin but prune is a physical merge and online snapshots
// carry RAM state).
type SnapshotPolicyConfig struct {
	// Type: none | simple (keep newest N auto-*) | age (delete auto-* older
	// than max_age_days) | rotation (hourly/daily/weekly tiers, Snapshoter.sh
	// schedule).
	Type string `yaml:"type" json:"type"`
	// Quiesce runs qga fsfreeze around each snapshot when the guest agent
	// answers (application-consistent; crash-consistent otherwise).
	Quiesce bool `yaml:"quiesce" json:"quiesce"`
	// Keep is simple's newest-N count.
	Keep int `yaml:"keep" json:"keep"`
	// MaxAgeDays is age's cutoff.
	MaxAgeDays int `yaml:"max_age_days" json:"max_age_days"`
	// Tiers are rotation's per-tier keep counts (hourly/daily/weekly).
	Tiers map[string]SnapshotTierConfig `yaml:"tiers" json:"tiers"`
}

// SnapshotsConfig controls the scheduled snapshot rotation service —
// zoneweaver's snapshots block (its Snapshoter.sh replacement) on this
// hypervisor's VBoxManage snapshot family. Per-machine override: the PUT
// /machines/{name} `snapshots` field (configuration.snapshots; type none
// disables per machine, null clears back to this default).
type SnapshotsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// IntervalMinutes is the simple/age cadence (rotation rides the fixed
	// hourly/daily/weekly wall-clock schedule).
	IntervalMinutes int                  `yaml:"interval_minutes" json:"interval_minutes"`
	DefaultPolicy   SnapshotPolicyConfig `yaml:"default_policy"   json:"default_policy"`
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

// Config is the root of config.yaml.
type Config struct {
	Server          ServerConfig          `yaml:"server"           json:"server"`
	SSL             SSLConfig             `yaml:"ssl"              json:"ssl"`
	CORS            CORSConfig            `yaml:"cors"             json:"cors"`
	UI              UIConfig              `yaml:"ui"               json:"ui"`
	Startup         StartupConfig         `yaml:"startup"          json:"startup"`
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
	CatalogSources  CatalogSourcesConfig  `yaml:"catalog_sources"  json:"catalog_sources"`
	ArtifactStorage ArtifactStorageConfig `yaml:"artifact_storage" json:"artifact_storage"`
	FileBrowser     FileBrowserConfig     `yaml:"file_browser"     json:"file_browser"`
	GuestAgent      GuestAgentConfig      `yaml:"guest_agent"      json:"guest_agent"`
	Snapshots       SnapshotsConfig       `yaml:"snapshots"        json:"snapshots"`
	Applications    []ApplicationConfig   `yaml:"applications"     json:"applications"`
	TicketSystem    TicketSystemConfig    `yaml:"ticket_system"    json:"ticket_system"`
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
		Browser: BrowserConfig{OpenOnStart: true},
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
			AutoDiscovery:     true,
			DiscoveryInterval: 300,
			ServerIDStart:     1,
			// Default true (Mark's ruling 2026-07-08): derived names carry the
			// partition-id prefix out of the box — the base's prefix_zone_names
			// default; the audit's B9 flip is closed.
			PrefixMachineNames: true,
			ShutdownTimeout:    120,
			KeepRunningOnExit:  true,
			ResourceValidation: ResourceValidationConfig{
				Enabled: true,
				// Storage defaults to "actual" here (the base defaults
				// committed): VirtualBox media are sparse files, so committed
				// sums against disk capacity over-reject on desktop hosts.
				Storage: ResourceCheckConfig{
					Enabled:    true,
					Strategy:   "actual",
					Thresholds: ResourceThresholdsConfig{Warning: 70, Critical: 80},
				},
				Memory: ResourceCheckConfig{
					Enabled:    true,
					Strategy:   "committed",
					Thresholds: ResourceThresholdsConfig{Warning: 80, Critical: 90},
				},
				CPU: CPUValidationConfig{
					Enabled:    true,
					Strategy:   "committed",
					HardLimit:  400,
					Thresholds: ResourceThresholdsConfig{Warning: 150, Critical: 300},
				},
			},
			Orchestration: OrchestrationConfig{
				Enabled:       false,
				Strategy:      "parallel_by_priority",
				PriorityDelay: 30,
			},
		},
		Provisioning: ProvisioningConfig{
			DefaultSyncMethod:            "rsync",
			PlaybookTimeoutSeconds:       21600,
			AnsibleInstallTimeoutSeconds: 300,
			HostHooks:                    true,
			SSH: ProvisioningSSHConfig{
				TimeoutSeconds:      300,
				PollIntervalSeconds: 10,
			},
			Network: ProvisioningNetworkConfig{
				Enabled:        true,
				Subnet:         "10.190.190.0/24",
				HostIP:         "10.190.190.1",
				Netmask:        "255.255.255.0",
				DHCPServerIP:   "10.190.190.2",
				DHCPRangeStart: "10.190.190.10",
				DHCPRangeEnd:   "10.190.190.254",
			},
		},
		TemplateSources: TemplateSourcesConfig{
			// The seed carries the registry's REAL name (Mark's ask 2026-07-09
			// — "Default Registry" was a placeholder the UI printed verbatim);
			// the default flag, not the name, selects the default source.
			Sources: []TemplateSourceConfig{{
				Name:    "STARTcloud BoxVault",
				URL:     "https://boxvault.startcloud.com",
				Enabled: true,
				Default: true,
			}},
		},
		CatalogSources: CatalogSourcesConfig{
			Sources: []CatalogSourceConfig{{
				Name:    "STARTcloud Provisioner Catalog",
				URL:     "https://provisioner-catalog.startcloud.com/catalog.json",
				Enabled: true,
				Default: true,
			}},
		},
		ArtifactStorage: ArtifactStorageConfig{
			Enabled:     true,
			MaxUploadGB: 50,
			Download:    ArtifactDownloadConfig{TimeoutSeconds: 3600},
			Scanning:    ArtifactScanningConfig{PeriodicScanInterval: 300},
			Paths:       []ArtifactPathConfig{},
		},
		FileBrowser: FileBrowserConfig{
			Enabled:           true,
			UploadSizeLimitGB: 50,
			Security: FileBrowserSecurityConfig{
				PreventTraversal:    true,
				MaxDirectoryEntries: 1000,
				MaxEditSizeMB:       100,
				// The base's device-tree guards, minus illumos-only paths —
				// harmless no-ops on Windows.
				ForbiddenPaths:    []string{"/dev", "/proc", "/sys"},
				ForbiddenPatterns: []string{},
			},
			Archive: FileBrowserArchiveConfig{
				Enabled:          true,
				SupportedFormats: []string{"zip", "tar", "tar.gz"},
				MaxArchiveSizeMB: 10240,
			},
		},
		GuestAgent: GuestAgentConfig{Enabled: true},
		// VBox-conservative retention defaults (Mark's ruling 2026-07-12):
		// zoneweaver's vocabulary with LOW keeps and off-by-default — prune is
		// a physical disk merge and online snapshots carry RAM state here,
		// unlike ZFS's free destroys.
		Snapshots: SnapshotsConfig{
			Enabled:         false,
			IntervalMinutes: 60,
			DefaultPolicy: SnapshotPolicyConfig{
				Type:       "none",
				Keep:       3,
				MaxAgeDays: 7,
				Tiers: map[string]SnapshotTierConfig{
					"hourly": {Keep: 2},
					"daily":  {Keep: 3},
					"weekly": {Keep: 2},
				},
			},
		},
		Applications: []ApplicationConfig{},
		TicketSystem: TicketSystemConfig{
			Enabled: true,
			BaseURL: "https://xd.prominic.net/app/apprequest.nsf/router?openagent",
			ReqType: "sso",
			Context: "https://github.com/Makr91/hyperweaver-agent",
		},
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
