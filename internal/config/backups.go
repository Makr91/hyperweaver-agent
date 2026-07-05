package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Config backups mirror the Node agent's BackupHelper: copies of config.yaml
// named config-<unix-ms>.yaml in a backups/ directory beside the config file.

// Backup describes one configuration backup on disk.
type Backup struct {
	Filename  string `json:"filename"`
	CreatedAt string `json:"createdAt"`
}

// backupNamePattern accepts only names the agent itself generates; combined
// with safepath.Under containment, client-supplied names cannot traverse.
var backupNamePattern = regexp.MustCompile(`^config-(\d+)\.yaml$`)

// BackupDir returns the backups directory beside the config file.
func (c *Config) BackupDir() string {
	return filepath.Join(filepath.Dir(c.path), "backups")
}

// CreateBackup copies the current config file into the backups directory.
func (c *Config) CreateBackup() (*Backup, error) {
	dir := c.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}

	timestamp := time.Now().UnixMilli()
	filename := fmt.Sprintf("config-%d.yaml", timestamp)
	target, err := safepath.Under(dir, filename)
	if err != nil {
		return nil, err
	}

	// Stream-copy through file handles: the sink-visible arguments are the
	// sanitized paths only, never file contents.
	src, err := os.Open(filepath.Clean(c.path))
	if err != nil {
		return nil, fmt.Errorf("read config for backup: %w", err)
	}
	defer func() {
		_ = src.Close()
	}()

	dst, err := os.OpenFile(filepath.Clean(target), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create backup: %w", err)
	}
	if _, cerr := io.Copy(dst, src); cerr != nil {
		_ = dst.Close()
		return nil, fmt.Errorf("write backup: %w", cerr)
	}
	if cerr := dst.Close(); cerr != nil {
		return nil, fmt.Errorf("finalize backup: %w", cerr)
	}

	return &Backup{
		Filename:  filename,
		CreatedAt: time.UnixMilli(timestamp).UTC().Format(time.RFC3339Nano),
	}, nil
}

// ListBackups returns all backups, newest first (Node-agent shape).
func (c *Config) ListBackups() ([]Backup, error) {
	dir := c.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	backups := make([]Backup, 0, len(entries))
	for _, entry := range entries {
		match := backupNamePattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		millis, perr := strconv.ParseInt(match[1], 10, 64)
		if perr != nil {
			continue
		}
		backups = append(backups, Backup{
			Filename:  entry.Name(),
			CreatedAt: time.UnixMilli(millis).UTC().Format(time.RFC3339Nano),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Filename > backups[j].Filename
	})
	return backups, nil
}

// resolveBackup validates a client-supplied backup name (agent-generated
// shape only) and returns its containment-checked path.
func (c *Config) resolveBackup(filename string) (string, error) {
	if !backupNamePattern.MatchString(filename) {
		return "", fmt.Errorf("invalid backup filename")
	}
	path, err := safepath.Under(c.BackupDir(), filename)
	if err != nil {
		return "", err
	}
	if _, serr := os.Stat(path); serr != nil {
		return "", serr
	}
	return path, nil
}

// DeleteBackup removes a backup file.
func (c *Config) DeleteBackup(filename string) error {
	path, err := c.resolveBackup(filename)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// RestoreBackup replaces the config file with a backup's contents, after
// validating the backup parses as a working configuration and backing up the
// current file (mirroring the Node agent's restore flow).
func (c *Config) RestoreBackup(filename string) error {
	path, err := c.resolveBackup(filename)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return err
	}
	if verr := validateConfigBytes(raw); verr != nil {
		return fmt.Errorf("backup is not a valid configuration: %w", verr)
	}

	if _, berr := c.CreateBackup(); berr != nil {
		return berr
	}
	return atomicWrite(c.path, raw)
}
