// Package config loads and provides the agent's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	BindAddress string `yaml:"bind_address" json:"bind_address"`
	Port        int    `yaml:"port"         json:"port"`
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
}

// Config is the root of config.yaml.
type Config struct {
	Server   ServerConfig   `yaml:"server"   json:"server"`
	UI       UIConfig       `yaml:"ui"       json:"ui"`
	Browser  BrowserConfig  `yaml:"browser"  json:"browser"`
	Logging  LoggingConfig  `yaml:"logging"  json:"logging"`
	APIKeys  APIKeysConfig  `yaml:"api_keys" json:"api_keys"`
	Updates  UpdatesConfig  `yaml:"updates"  json:"updates"`
	APIDocs  APIDocsConfig  `yaml:"api_docs" json:"api_docs"`
	Data     DataConfig     `yaml:"data"     json:"data"`
	Tasks    TasksConfig    `yaml:"tasks"    json:"tasks"`
	Machines MachinesConfig `yaml:"machines" json:"machines"`

	// path is where this configuration was loaded from; the setup token, key
	// store, protocol-handoff secret, and config backups live beside it.
	path string
}

// defaultConfigYAML is written verbatim on first run so the on-disk file keeps
// its comments (a plain Marshal of Config would lose them).
const defaultConfigYAML = `# Hyperweaver Agent configuration
# https://github.com/Makr91/hyperweaver-agent

server:
  # Address the web server binds to. Keep 127.0.0.1 unless you know you want
  # the agent reachable from other machines.
  bind_address: 127.0.0.1
  port: 9420

ui:
  # Serve the bundled Hyperweaver UI at /ui/ (and / redirects there).
  enabled: true
  # Optional: serve the UI from this directory instead of the copy embedded in
  # the binary. Leave empty for normal operation.
  path: ''

browser:
  # Optional: full path to the browser the tray "Open" action should launch
  # (an executable, or a .app bundle on macOS). Empty = system default browser.
  path: ''

logging:
  # error | warn | info | debug
  level: info
  # Also log human-readable output to the console (visible when the agent is
  # started from a terminal; GUI builds on Windows have no console).
  console: true
  # Log file location. Empty = <config dir>/logs/agent.log
  file: ''
  max_size_mb: 20
  max_backups: 5

api_keys:
  # Allow POST /api-keys/bootstrap to create the first API key.
  bootstrap_enabled: true
  # Lock the bootstrap endpoint once any key exists.
  bootstrap_auto_disable: true
  # Require the setup (claim) token — written to setup.token beside this file
  # and printed to the startup log — as proof of host ownership.
  bootstrap_require_claim_token: true
  # Bcrypt cost for stored key hashes.
  hash_rounds: 12
  # Random bytes of key material (base64url-encoded after the hw_ prefix).
  key_length: 64

updates:
  # Version document the update check compares against (JSON: version,
  # releaseUrl, releaseDate, changelog). Empty disables update checking.
  versioninfo_url: https://github.com/Makr91/hyperweaver-agent/releases/latest/download/update-info.json

api_docs:
  # Serve the interactive Agent API documentation (Swagger UI) at /api-docs.
  enabled: true

data:
  # Root directory for agent data: the SQLite databases (tasks.sqlite,
  # agent.sqlite) today; machine directories, provisioners, and the file
  # cache in later releases. Empty = the per-OS local app-data default
  # (%LOCALAPPDATA%\hyperweaver-agent on Windows,
  # ~/Library/Application Support/hyperweaver-agent on macOS,
  # ~/.local/share/hyperweaver-agent on Linux).
  dir: ''

tasks:
  # Seconds between task-queue polls.
  poll_interval_seconds: 2
  # Maximum number of tasks running at once.
  max_concurrent: 5
  # Default limit for GET /tasks when the request does not send one.
  default_pagination_limit: 50
  # Completed/failed/cancelled tasks older than this many days are deleted
  # by the periodic cleanup.
  retention_days: 30
  output:
    # Capture task output (live streaming + persistence).
    enabled: true
    # full keeps every output line; circular caps the in-memory buffer at
    # circular_max_lines, dropping the oldest.
    mode: full
    circular_max_lines: 10000
    # Seconds between database flushes of a running task's output.
    flush_interval_seconds: 10
    # Also write a plain-text per-task log file when a task finishes.
    persist_log_file: true
    # Directory for those log files. Empty = <config dir>/logs/tasks
    log_directory: ''

machines:
  # Create a periodic background discover task that reconciles the registry
  # against VirtualBox and vagrant (imports machines built outside the agent,
  # detects external shutdowns). The startup discovery always runs.
  auto_discovery: true
  # Seconds between periodic discover tasks.
  discovery_interval: 300
  # Lowest auto-assigned server_id.
  server_id_start: 1
`

// Default returns the built-in configuration values.
func Default() *Config {
	return &Config{
		Server:  ServerConfig{BindAddress: "127.0.0.1", Port: 9420},
		UI:      UIConfig{Enabled: true},
		Browser: BrowserConfig{},
		Logging: LoggingConfig{Level: "info", Console: true, MaxSizeMB: 20, MaxBackups: 5},
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
		Data:    DataConfig{},
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
		},
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

func ensureDefaultFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat config %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(defaultConfigYAML), 0o600); err != nil {
		return fmt.Errorf("write default config: %w", err)
	}
	return nil
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range 1-65535", c.Server.Port)
	}
	if c.Server.BindAddress != "" && net.ParseIP(c.Server.BindAddress) == nil {
		return fmt.Errorf("server.bind_address %q is not an IP address", c.Server.BindAddress)
	}
	switch c.Logging.Level {
	case "error", "warn", "info", "debug":
	default:
		return fmt.Errorf("logging.level %q must be one of error, warn, info, debug", c.Logging.Level)
	}
	if c.APIKeys.HashRounds < 4 || c.APIKeys.HashRounds > 20 {
		return fmt.Errorf("api_keys.hash_rounds %d out of range 4-20", c.APIKeys.HashRounds)
	}
	if c.APIKeys.KeyLength < 16 || c.APIKeys.KeyLength > 256 {
		return fmt.Errorf("api_keys.key_length %d out of range 16-256", c.APIKeys.KeyLength)
	}
	if c.Tasks.PollIntervalSeconds < 1 || c.Tasks.PollIntervalSeconds > 60 {
		return fmt.Errorf("tasks.poll_interval_seconds %d out of range 1-60", c.Tasks.PollIntervalSeconds)
	}
	if c.Tasks.MaxConcurrent < 1 || c.Tasks.MaxConcurrent > 64 {
		return fmt.Errorf("tasks.max_concurrent %d out of range 1-64", c.Tasks.MaxConcurrent)
	}
	switch c.Tasks.Output.Mode {
	case "full", "circular":
	default:
		return fmt.Errorf("tasks.output.mode %q must be full or circular", c.Tasks.Output.Mode)
	}
	if c.Tasks.Output.CircularMaxLines < 100 {
		return fmt.Errorf("tasks.output.circular_max_lines %d must be at least 100", c.Tasks.Output.CircularMaxLines)
	}
	if c.Tasks.Output.FlushIntervalSeconds < 1 || c.Tasks.Output.FlushIntervalSeconds > 300 {
		return fmt.Errorf("tasks.output.flush_interval_seconds %d out of range 1-300", c.Tasks.Output.FlushIntervalSeconds)
	}
	if c.Tasks.DefaultPaginationLimit < 1 || c.Tasks.DefaultPaginationLimit > 1000 {
		return fmt.Errorf("tasks.default_pagination_limit %d out of range 1-1000", c.Tasks.DefaultPaginationLimit)
	}
	if c.Tasks.RetentionDays < 1 || c.Tasks.RetentionDays > 3650 {
		return fmt.Errorf("tasks.retention_days %d out of range 1-3650", c.Tasks.RetentionDays)
	}
	if c.Machines.DiscoveryInterval < 10 || c.Machines.DiscoveryInterval > 86400 {
		return fmt.Errorf("machines.discovery_interval %d out of range 10-86400", c.Machines.DiscoveryInterval)
	}
	if c.Machines.ServerIDStart < 1 || c.Machines.ServerIDStart > 99999999 {
		return fmt.Errorf("machines.server_id_start %d out of range 1-99999999", c.Machines.ServerIDStart)
	}
	return nil
}

// ListenAddr returns the host:port the HTTP server binds to.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.BindAddress, strconv.Itoa(c.Server.Port))
}

// BaseURL returns the agent's locally reachable HTTP origin. A wildcard bind
// address is rewritten to a loopback address the local machine can reach.
func (c *Config) BaseURL() string {
	host := c.Server.BindAddress
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(c.Server.Port))
}

// LocalURL returns the URL the tray "Open" action launches.
func (c *Config) LocalURL() string {
	return c.BaseURL() + "/ui/"
}

// LogFilePath returns the configured log file, defaulting to
// <config dir>/logs/agent.log.
func (c *Config) LogFilePath() (string, error) {
	if c.Logging.File != "" {
		return c.Logging.File, nil
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "logs", "agent.log"), nil
}

// Path returns where this configuration was loaded from.
func (c *Config) Path() string {
	return c.path
}

// SetupTokenPath returns the setup (claim) token location: setup.token beside
// the loaded configuration file, mirroring the Node agent.
func (c *Config) SetupTokenPath() string {
	return filepath.Join(filepath.Dir(c.path), "setup.token")
}

// KeyStorePath returns the API-key store location: keys.json beside the
// loaded configuration file.
func (c *Config) KeyStorePath() string {
	return filepath.Join(filepath.Dir(c.path), "keys.json")
}

// ProtocolSecretPath returns the hwa:// handoff-secret location:
// protocol.secret beside the loaded configuration file.
func (c *Config) ProtocolSecretPath() string {
	return filepath.Join(filepath.Dir(c.path), "protocol.secret")
}

// DataDir returns the agent's data root: data.dir when configured, else the
// per-OS local app-data location — deliberately NOT the (Windows-roaming)
// config directory, since machine working copies and databases must not ride
// a roaming profile.
func (c *Config) DataDir() (string, error) {
	if c.Data.Dir != "" {
		return safepath.CleanAbs(c.Data.Dir)
	}
	switch runtime.GOOS {
	case "windows":
		// os.UserCacheDir is %LocalAppData% on Windows.
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("resolve local app data dir: %w", err)
		}
		return filepath.Join(base, "hyperweaver-agent"), nil
	case "darwin":
		// macOS has no roaming/local split; Application Support serves both.
		base, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("resolve application support dir: %w", err)
		}
		return filepath.Join(base, "hyperweaver-agent"), nil
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "hyperweaver-agent"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		return filepath.Join(home, ".local", "share", "hyperweaver-agent"), nil
	}
}

// TasksDBPath returns the task-queue database location: tasks.sqlite under
// the data root (its own file so the queue's write churn never contends
// with core state — architecture D-A).
func (c *Config) TasksDBPath() (string, error) {
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tasks.sqlite"), nil
}

// AgentDBPath returns the core-state database location: agent.sqlite under
// the data root (machines, templates, artifacts — populated by later phases).
func (c *Config) AgentDBPath() (string, error) {
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent.sqlite"), nil
}

// TaskLogDir returns where per-task output log files land, defaulting to
// logs/tasks beside the agent log.
func (c *Config) TaskLogDir() (string, error) {
	if c.Tasks.Output.LogDirectory != "" {
		return c.Tasks.Output.LogDirectory, nil
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "logs", "tasks"), nil
}
