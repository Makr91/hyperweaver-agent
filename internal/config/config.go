// Package config loads and provides the agent's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Config is the root of config.yaml.
type Config struct {
	Server  ServerConfig  `yaml:"server"   json:"server"`
	UI      UIConfig      `yaml:"ui"       json:"ui"`
	Browser BrowserConfig `yaml:"browser"  json:"browser"`
	Logging LoggingConfig `yaml:"logging"  json:"logging"`
	APIKeys APIKeysConfig `yaml:"api_keys" json:"api_keys"`
	Updates UpdatesConfig `yaml:"updates"  json:"updates"`

	// path is where this configuration was loaded from; the setup token, key
	// store, and config backups live beside it.
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
	return nil
}

// ListenAddr returns the host:port the HTTP server binds to.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.Server.BindAddress, strconv.Itoa(c.Server.Port))
}

// LocalURL returns the URL the tray "Open" action launches. A wildcard bind
// address is rewritten to a loopback address the browser can actually reach.
func (c *Config) LocalURL() string {
	host := c.Server.BindAddress
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s/ui/", net.JoinHostPort(host, strconv.Itoa(c.Server.Port)))
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
