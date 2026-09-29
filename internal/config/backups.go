package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Backup describes one timestamped copy of the five configuration files.
type Backup struct {
	ID        string   `json:"id"`
	CreatedAt string   `json:"created_at"`
	Files     []string `json:"files"`
}

var backupIDPattern = regexp.MustCompile(`^\d{13}$`)

// BackupDir answers the backups directory beside the configuration files.
func (c *Config) BackupDir() string {
	return filepath.Join(c.dir, "backups")
}

// CreateBackup copies every configuration file into a new timestamped folder.
func (c *Config) CreateBackup() (*Backup, error) {
	id := strconv.FormatInt(time.Now().UnixMilli(), 10)
	dir, err := safepath.Under(c.BackupDir(), id)
	if err != nil {
		return nil, err
	}
	if merr := os.MkdirAll(dir, 0o700); merr != nil {
		return nil, fmt.Errorf("create backup dir: %w", merr)
	}
	backup := &Backup{ID: id, CreatedAt: backupTime(id), Files: []string{}}
	for _, name := range Names {
		raw, rerr := os.ReadFile(filepath.Join(c.dir, name+".config.yaml"))
		if rerr != nil {
			return nil, fmt.Errorf("read %s for backup: %w", name, rerr)
		}
		if werr := safepath.WriteFile(filepath.Join(dir, name+".config.yaml"), raw, 0o600); werr != nil {
			return nil, fmt.Errorf("write backup: %w", werr)
		}
		backup.Files = append(backup.Files, name)
	}
	return backup, nil
}

func backupTime(id string) string {
	millis, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return ""
	}
	return time.UnixMilli(millis).UTC().Format(time.RFC3339)
}

// ListBackups answers every backup, newest first.
func (c *Config) ListBackups() ([]Backup, error) {
	if err := os.MkdirAll(c.BackupDir(), 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(c.BackupDir())
	if err != nil {
		return nil, err
	}
	backups := []Backup{}
	for _, entry := range entries {
		if !entry.IsDir() || !backupIDPattern.MatchString(entry.Name()) {
			continue
		}
		files := []string{}
		for _, name := range Names {
			if _, serr := os.Stat(filepath.Join(c.BackupDir(), entry.Name(), name+".config.yaml")); serr == nil {
				files = append(files, name)
			}
		}
		backups = append(backups, Backup{ID: entry.Name(), CreatedAt: backupTime(entry.Name()), Files: files})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].ID > backups[j].ID })
	return backups, nil
}

func (c *Config) resolveBackup(id string) (string, error) {
	if !backupIDPattern.MatchString(id) {
		return "", errors.New("invalid backup id")
	}
	dir, err := safepath.Under(c.BackupDir(), id)
	if err != nil {
		return "", err
	}
	if _, serr := os.Stat(dir); serr != nil {
		return "", serr
	}
	return dir, nil
}

// DeleteBackup removes one backup folder.
func (c *Config) DeleteBackup(id string) error {
	dir, err := c.resolveBackup(id)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// RestoreBackup validates every file of a backup and writes them through the engine after backing up the current files.
func (c *Config) RestoreBackup(id string) error {
	dir, err := c.resolveBackup(id)
	if err != nil {
		return err
	}
	documents := map[string]map[string]any{}
	for _, name := range Names {
		raw, rerr := os.ReadFile(filepath.Join(dir, name+".config.yaml"))
		if errors.Is(rerr, os.ErrNotExist) {
			continue
		}
		if rerr != nil {
			return rerr
		}
		document := map[string]any{}
		if uerr := yaml.Unmarshal(raw, &document); uerr != nil {
			return fmt.Errorf("backup %s is not valid YAML: %w", name, uerr)
		}
		documents[name] = document
	}
	if _, berr := c.CreateBackup(); berr != nil {
		return berr
	}
	for _, name := range Names {
		document, present := documents[name]
		if !present {
			continue
		}
		if rerr := c.engine.Restore(name, document, "agent"); rerr != nil {
			return rerr
		}
	}
	return c.fill()
}
