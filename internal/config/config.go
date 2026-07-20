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
