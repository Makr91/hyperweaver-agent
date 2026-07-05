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
)

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	BindAddress string `yaml:"bind_address"`
	Port        int    `yaml:"port"`
}

// UIConfig controls serving of the embedded Hyperweaver UI.
type UIConfig struct {
	Enabled bool `yaml:"enabled"`
	// Path optionally serves the UI from a directory on disk instead of the
	// artifact embedded in the binary (dev override, mirrors the Node agent).
	Path string `yaml:"path"`
}

// BrowserConfig controls how the tray "Open" action launches a browser.
type BrowserConfig struct {
	// Path is an optional browser executable (or macOS .app bundle). Empty
	// means the operating system's default browser.
	Path string `yaml:"path"`
}

// LoggingConfig controls slog output.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Console    bool   `yaml:"console"`
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

// Config is the root of config.yaml.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	UI      UIConfig      `yaml:"ui"`
	Browser BrowserConfig `yaml:"browser"`
	Logging LoggingConfig `yaml:"logging"`
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
`

// Default returns the built-in configuration values.
func Default() *Config {
	return &Config{
		Server:  ServerConfig{BindAddress: "127.0.0.1", Port: 9420},
		UI:      UIConfig{Enabled: true},
		Browser: BrowserConfig{},
		Logging: LoggingConfig{Level: "info", Console: true, MaxSizeMB: 20, MaxBackups: 5},
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
		if err := ensureDefaultFile(resolved); err != nil {
			return nil, "", err
		}
	}

	data, err := os.ReadFile(resolved) // #nosec G304 -- path is the user's own config file
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
