package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// SSLKeyPath returns the TLS private key location: ssl.key_path when
// configured, else ssl/server.key beside the loaded configuration file.
func (c *Config) SSLKeyPath() string {
	if c.SSL.KeyPath != "" {
		return c.SSL.KeyPath
	}
	return filepath.Join(filepath.Dir(c.path), "ssl", "server.key")
}

// SSLCertPath returns the TLS certificate location: ssl.cert_path when
// configured, else ssl/server.crt beside the loaded configuration file.
func (c *Config) SSLCertPath() string {
	if c.SSL.CertPath != "" {
		return c.SSL.CertPath
	}
	return filepath.Join(filepath.Dir(c.path), "ssl", "server.crt")
}

// SSLCACertPath returns the CA certificate location: ssl.ca_cert_path when
// configured, else ssl/ca.crt beside the loaded configuration file.
func (c *Config) SSLCACertPath() string {
	if c.SSL.CACertPath != "" {
		return c.SSL.CACertPath
	}
	return filepath.Join(filepath.Dir(c.path), "ssl", "ca.crt")
}

// SSLCAKeyPath returns the CA private-key location: ssl.ca_key_path when
// configured, else ssl/ca.key beside the loaded configuration file.
func (c *Config) SSLCAKeyPath() string {
	if c.SSL.CAKeyPath != "" {
		return c.SSL.CAKeyPath
	}
	return filepath.Join(filepath.Dir(c.path), "ssl", "ca.key")
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

// MonitoringDBPath returns a telemetry database location under the data
// root: monitoring-<kind>.sqlite (kind ∈ cpu, memory, network). One file per
// data type, each with its own WAL, so telemetry write churn never contends
// with the main databases or with the other telemetry families (Mark's
// ruling, 2026-07-05 — the single-file IO contention zoneweaver hits).
func (c *Config) MonitoringDBPath(kind string) (string, error) {
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "monitoring-"+kind+".sqlite"), nil
}

// ProvisionersDir returns the provisioner package registry root:
// provisioning.provisioners_dir when configured, else provisioners under the
// data root.
func (c *Config) ProvisionersDir() (string, error) {
	if c.Provisioning.ProvisionersDir != "" {
		return safepath.CleanAbs(c.Provisioning.ProvisionersDir)
	}
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "provisioners"), nil
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
