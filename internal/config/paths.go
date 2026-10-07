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
	return filepath.Join(c.dir, "ssl", "server.key")
}

// SSLCertPath returns the TLS certificate location: ssl.cert_path when
// configured, else ssl/server.crt beside the loaded configuration file.
func (c *Config) SSLCertPath() string {
	if c.SSL.CertPath != "" {
		return c.SSL.CertPath
	}
	return filepath.Join(c.dir, "ssl", "server.crt")
}

// SSLCACertPath returns the CA certificate location: ssl.ca_cert_path when
// configured, else ssl/ca.crt beside the loaded configuration file.
func (c *Config) SSLCACertPath() string {
	if c.SSL.CACertPath != "" {
		return c.SSL.CACertPath
	}
	return filepath.Join(c.dir, "ssl", "ca.crt")
}

// SSLCAKeyPath returns the CA private-key location: ssl.ca_key_path when
// configured, else ssl/ca.key beside the loaded configuration file.
func (c *Config) SSLCAKeyPath() string {
	if c.SSL.CAKeyPath != "" {
		return c.SSL.CAKeyPath
	}
	return filepath.Join(c.dir, "ssl", "ca.key")
}

// VRDECertRoot returns where per-machine VRDE TLS material lives:
// ssl/vrde/<machine>/ beside the loaded configuration file — surviving as
// long as the configuration does. Shared by the create executor, the
// browser-RDP bridge's self-heal, and the vrde-tls endpoint.
func (c *Config) VRDECertRoot() string {
	return filepath.Join(c.dir, "ssl", "vrde")
}

// LogFilePath returns the configured log file, defaulting to
// <config dir>/logs/agent.log.
func (c *Config) LogFilePath() (string, error) {
	if c.Logging.File != "" {
		return c.Logging.File, nil
	}
	return filepath.Join(c.dir, "logs", "agent.log"), nil
}

// SetupTokenPath returns the setup token location: setup.token beside the
// configuration files.
func (c *Config) SetupTokenPath() string {
	return filepath.Join(c.dir, "setup.token")
}

// KeyStorePath returns the API-key store location: keys.json beside the
// configuration files.
func (c *Config) KeyStorePath() string {
	return filepath.Join(c.dir, "keys.json")
}

// SessionStorePath returns the browser session store location: sessions.json
// beside the configuration files.
func (c *Config) SessionStorePath() string {
	return filepath.Join(c.dir, "sessions.json")
}

// ProtocolSecretPath returns the hwa:// handoff-secret location:
// protocol.secret beside the configuration files.
func (c *Config) ProtocolSecretPath() string {
	return filepath.Join(c.dir, "protocol.secret")
}

// SecretsPath returns the global secrets store location: secrets.yaml
// beside the configuration files (architecture D-C — its own store so the
// configuration routes keep serving just the configuration documents).
func (c *Config) SecretsPath() string {
	return filepath.Join(c.dir, "secrets.yaml")
}

// DataDir returns the agent's data root: data.dir when configured, else the
// per-OS local app-data location.
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

func (c *Config) definitionsDir() (string, error) {
	if c.Data.Dir == "" && runtime.GOOS == "windows" {
		return c.dir, nil
	}
	return c.DataDir()
}

// ProvisionersDir returns the provisioner package registry root.
func (c *Config) ProvisionersDir() (string, error) {
	if c.Provisioning.ProvisionersDir != "" {
		return safepath.CleanAbs(c.Provisioning.ProvisionersDir)
	}
	dir, err := c.definitionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "provisioners"), nil
}

// MachinesDir returns the root of the per-machine working directories.
func (c *Config) MachinesDir() (string, error) {
	if c.Provisioning.MachinesDir != "" {
		return safepath.CleanAbs(c.Provisioning.MachinesDir)
	}
	dir, err := c.definitionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "machines"), nil
}

// DownloadsDir returns where the update flow lands installers: downloads
// under the data root (SHI's downloads directory).
func (c *Config) DownloadsDir() (string, error) {
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "downloads"), nil
}

// ArtifactsRootDir returns the built-in storage locations' parent:
// artifact_storage.dir when configured, else artifacts under the data root.
func (c *Config) ArtifactsRootDir() (string, error) {
	if c.ArtifactStorage.Dir != "" {
		return safepath.CleanAbs(c.ArtifactStorage.Dir)
	}
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "artifacts"), nil
}

// TemplatesDir returns the box-template storage root:
// template_sources.local_storage_path when configured, else templates under
// the data root.
func (c *Config) TemplatesDir() (string, error) {
	if c.TemplateSources.LocalStoragePath != "" {
		return safepath.CleanAbs(c.TemplateSources.LocalStoragePath)
	}
	dir, err := c.DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "templates"), nil
}

// ProvisionKeyPath returns the agent's provisioning SSH key location:
// provisioning.ssh.key_path when configured, else ssh/provision_key beside
// the loaded configuration file.
func (c *Config) ProvisionKeyPath() string {
	if c.Provisioning.SSH.KeyPath != "" {
		return c.Provisioning.SSH.KeyPath
	}
	return filepath.Join(c.dir, "ssh", "provision_key")
}

// TaskLogDir returns where per-task output log files land, defaulting to
// logs/tasks beside the agent log.
func (c *Config) TaskLogDir() (string, error) {
	if c.Tasks.Output.LogDirectory != "" {
		return c.Tasks.Output.LogDirectory, nil
	}
	return filepath.Join(c.dir, "logs", "tasks"), nil
}
