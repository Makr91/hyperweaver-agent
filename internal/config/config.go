// Package config loads and provides the agent's YAML configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/configengine"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Config is the typed view over the five configuration files.
type Config struct {
	Server          ServerConfig                 `yaml:"server"           json:"server"`
	SSL             SSLConfig                    `yaml:"ssl"              json:"ssl"`
	CORS            CORSConfig                   `yaml:"cors"             json:"cors"`
	UI              UIConfig                     `yaml:"ui"               json:"ui"`
	Startup         StartupConfig                `yaml:"startup"          json:"startup"`
	Browser         BrowserConfig                `yaml:"browser"          json:"browser"`
	Logging         LoggingConfig                `yaml:"logging"          json:"logging"`
	APIKeys         APIKeysConfig                `yaml:"api_keys"         json:"api_keys"`
	OIDC            oidcConfig                   `yaml:"oidc"             json:"oidc"`
	Updates         UpdatesConfig                `yaml:"updates"          json:"updates"`
	APIDocs         APIDocsConfig                `yaml:"api_docs"         json:"api_docs"`
	Stats           StatsConfig                  `yaml:"stats"            json:"stats"`
	Data            DataConfig                   `yaml:"data"             json:"data"`
	Database        DatabaseConfig               `yaml:"database"         json:"database"`
	Tasks           TasksConfig                  `yaml:"tasks"            json:"tasks"`
	Machines        MachinesConfig               `yaml:"machines"         json:"machines"`
	Provisioning    ProvisioningConfig           `yaml:"provisioning"     json:"provisioning"`
	TemplateSources TemplateSourcesConfig        `yaml:"template_sources" json:"template_sources"`
	CatalogSources  CatalogSourcesConfig         `yaml:"catalog_sources"  json:"catalog_sources"`
	ArtifactStorage ArtifactStorageConfig        `yaml:"artifact_storage" json:"artifact_storage"`
	FileBrowser     FileBrowserConfig            `yaml:"file_browser"     json:"file_browser"`
	GuestAgent      GuestAgentConfig             `yaml:"guest_agent"      json:"guest_agent"`
	Snapshots       SnapshotsConfig              `yaml:"snapshots"        json:"snapshots"`
	Applications    map[string]ApplicationConfig `yaml:"applications"     json:"applications"`
	TicketSystem    TicketSystemConfig           `yaml:"ticket_system"    json:"ticket_system"`
	Cleanup         CleanupConfig                `yaml:"cleanup"          json:"cleanup"`
	Monitoring      MonitoringConfig             `yaml:"monitoring"       json:"monitoring"`
	HostPower       HostPowerConfig              `yaml:"host_power"       json:"host_power"`

	dir    string
	engine *configengine.Engine
}

// fileOfSection names the configuration file each top-level section lives in.
var fileOfSection = map[string]string{
	"server": "app", "ssl": "app", "cors": "app", "ui": "app", "startup": "app",
	"browser": "app", "logging": "app", "updates": "app", "api_docs": "app",
	"stats": "app", "data": "app", "tasks": "app", "cleanup": "app",
	"monitoring": "app", "host_power": "app", "file_browser": "app",
	"ticket_system": "app", "applications": "app",
	"api_keys": "auth", "oidc": "auth",
	"database": "db",
	"machines": "machines", "provisioning": "machines", "guest_agent": "machines", "snapshots": "machines",
	"template_sources": "storage", "catalog_sources": "storage", "artifact_storage": "storage",
}

// DefaultDir answers the per-user configuration directory, CONFIG_DIR when set.
func DefaultDir() (string, error) {
	if dir := os.Getenv("CONFIG_DIR"); dir != "" {
		return safepath.CleanAbs(dir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(base, "hyperweaver-agent"), nil
}

// Options shape one load.
type Options struct {
	Dir           string
	Seed          bool
	SetupComplete func() bool
}

// Load builds the engine over the configuration directory, loads every file and fills the typed view.
func Load(options Options) (*Config, error) {
	dir := options.Dir
	if dir == "" {
		defaultDir, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = defaultDir
	}
	dir, err := safepath.CleanAbs(dir)
	if err != nil {
		return nil, err
	}
	if options.Seed {
		if serr := ensureSeeds(dir); serr != nil {
			return nil, serr
		}
	}
	cfg := &Config{dir: dir}
	cfg.engine = configengine.New(dir, Names, SchemaFS(), configengine.Hooks{
		Writable:      cfg.codeRules,
		SetupComplete: options.SetupComplete,
	})
	if lerr := cfg.engine.Load(); lerr != nil {
		return nil, lerr
	}
	if ferr := cfg.fill(); ferr != nil {
		return nil, ferr
	}
	return cfg, nil
}

func (c *Config) fill() error {
	merged := map[string]any{}
	for _, name := range Names {
		for key, value := range c.engine.Get(name) {
			if key == "schemaVersion" {
				continue
			}
			merged[key] = value
		}
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	fresh := Config{dir: c.dir, engine: c.engine, Applications: map[string]ApplicationConfig{}}
	if uerr := json.Unmarshal(raw, &fresh); uerr != nil {
		return fmt.Errorf("fill configuration: %w", uerr)
	}
	*c = fresh
	return nil
}

// Engine answers the configuration engine.
func (c *Config) Engine() *configengine.Engine {
	return c.engine
}

// Dir answers the configuration directory.
func (c *Config) Dir() string {
	return c.dir
}

// ListenAddr returns the host:port the HTTP server binds to.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.BindAddress, strconv.Itoa(c.Server.Port))
}

// HTTPSListenAddr returns the host:port the HTTPS server binds to.
func (c *Config) HTTPSListenAddr() string {
	return net.JoinHostPort(c.Server.BindAddress, strconv.Itoa(c.Server.HTTPSPort))
}

// BaseURL returns the agent's locally reachable origin; with SSL enabled it is the HTTPS one.
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
	return c.BaseURL() + "/"
}
