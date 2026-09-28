package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/Makr91/hyperweaver-agent/internal/locations"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

type StoragePathConfig struct {
	DisplayName string `yaml:"display_name" json:"display_name"`
	Path        string `yaml:"path"         json:"path"`
	Enabled     bool   `yaml:"enabled"      json:"enabled"`
	Default     bool   `yaml:"default"      json:"default"`
}

var storagePathIDPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

func ValidStoragePathID(id string) bool {
	return id != locations.BuiltinID && storagePathIDPattern.MatchString(id)
}

func (c *Config) StoragePaths(kind locations.Kind) map[string]StoragePathConfig {
	switch kind {
	case locations.Machines:
		return c.Provisioning.MachinesPaths
	case locations.Provisioners:
		return c.Provisioning.ProvisionersPaths
	case locations.Templates:
		return c.TemplateSources.StoragePaths
	default:
		return nil
	}
}

func (c *Config) SetStoragePaths(kind locations.Kind, paths map[string]StoragePathConfig) {
	switch kind {
	case locations.Machines:
		c.Provisioning.MachinesPaths = paths
	case locations.Provisioners:
		c.Provisioning.ProvisionersPaths = paths
	case locations.Templates:
		c.TemplateSources.StoragePaths = paths
	}
}

func (c *Config) builtinStoragePath(kind locations.Kind) (string, error) {
	switch kind {
	case locations.Machines:
		return c.MachinesDir()
	case locations.Provisioners:
		return c.ProvisionersDir()
	case locations.Templates:
		return c.TemplatesDir()
	default:
		return "", fmt.Errorf("unknown storage kind %q", kind)
	}
}

func (c *Config) StorageLocations(kind locations.Kind) ([]locations.Location, error) {
	builtin, err := c.builtinStoragePath(kind)
	if err != nil {
		return nil, err
	}
	paths := c.StoragePaths(kind)
	ids := make([]string, 0, len(paths))
	for id := range paths {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	list := make([]locations.Location, 0, len(ids)+1)
	list = append(list, locations.Location{
		ID:          locations.BuiltinID,
		DisplayName: "Built-in",
		Path:        builtin,
		Enabled:     true,
		Builtin:     true,
	})
	for _, id := range ids {
		entry := paths[id]
		clean, cerr := safepath.CleanAbs(entry.Path)
		if cerr != nil {
			return nil, cerr
		}
		list = append(list, locations.Location{
			ID:          id,
			DisplayName: entry.DisplayName,
			Path:        clean,
			Enabled:     entry.Enabled,
			Default:     entry.Default,
		})
	}
	return list, nil
}

func (c *Config) LoadStorageLocations(set *locations.Set, kind locations.Kind) error {
	list, err := c.StorageLocations(kind)
	if err != nil {
		return err
	}
	for i := range list {
		if !list[i].Enabled || list[i].Builtin {
			continue
		}
		if merr := os.MkdirAll(list[i].Path, 0o750); merr != nil {
			slog.Warn("storage path unreachable; disabled until it is reachable again",
				"type", kind, "id", list[i].ID, "path", list[i].Path, "error", merr)
			list[i].Enabled = false
		}
	}
	set.Replace(kind, list)
	return nil
}

func validateStoragePaths(key string, paths map[string]StoragePathConfig) error {
	defaults := 0
	seen := make([]string, 0, len(paths))
	ids := make([]string, 0, len(paths))
	for id := range paths {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		entry := paths[id]
		if !ValidStoragePathID(id) {
			return fmt.Errorf("%s.%s: the key must match ^[a-z0-9_]+$ and must not be %q", key, id, locations.BuiltinID)
		}
		if entry.DisplayName == "" {
			return fmt.Errorf("%s.%s.display_name is required", key, id)
		}
		if entry.Path == "" || !filepath.IsAbs(filepath.FromSlash(entry.Path)) {
			return fmt.Errorf("%s.%s.path %q must be an absolute path", key, id, entry.Path)
		}
		for _, other := range seen {
			if locations.SamePath(other, entry.Path) {
				return fmt.Errorf("%s.%s.path %q is already a storage path", key, id, entry.Path)
			}
		}
		seen = append(seen, entry.Path)
		if entry.Default {
			defaults++
		}
	}
	if defaults > 1 {
		return fmt.Errorf("%s: only one entry may be the default", key)
	}
	return nil
}
