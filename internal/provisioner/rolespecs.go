package provisioner

// The derived role-specs cache — OURS, not the package's (zoneweaver's
// lib/ProvisionerRegistry role-specs half, ported 1:1 per Mark's
// argument-specs ruling 2026-07-12): every shipped role's
// meta/argument_specs.yml folded into role-specs.yml BESIDE provisioner.yml
// (rewriting provisioner.yml itself would re-serialize the package manifest
// and destroy its comments/release stamp). Rebuilt at import and by POST
// /provisioning/provisioners/refresh-specs; a missing cache self-heals at
// read (hand-dropped packages).

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// roleSpecsFile is the cache's name inside a version directory.
const roleSpecsFile = "role-specs.yml"

// RoleSpec is one role's cached argument spec — the main entry point's
// short_description and option schemas, the UI's per-role knob-form feed.
type RoleSpec struct {
	Collection       string         `json:"collection"        yaml:"collection"`
	ShortDescription string         `json:"short_description" yaml:"short_description"`
	Options          map[string]any `json:"options"           yaml:"options"`
}

// RoleSpecs is the cache document.
type RoleSpecs struct {
	Roles map[string]RoleSpec `json:"roles" yaml:"roles"`
}

// RefreshedSpecs is one version's refresh outcome.
type RefreshedSpecs struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Roles   int    `json:"roles"`
}

// deriveRoleSpecs walks the version's shipped ansible_collections and folds
// every role's argument specs into one map.
func deriveRoleSpecs(versionRoot string) map[string]RoleSpec {
	roles := map[string]RoleSpec{}
	collectionsDir := filepath.Join(versionRoot, "provisioners", "ansible_collections")
	namespaces, err := os.ReadDir(collectionsDir)
	if err != nil {
		return roles
	}
	for _, namespace := range namespaces {
		if !namespace.IsDir() {
			continue
		}
		collections, cerr := os.ReadDir(filepath.Join(collectionsDir, namespace.Name()))
		if cerr != nil {
			continue
		}
		for _, collection := range collections {
			if !collection.IsDir() {
				continue
			}
			rolesDir := filepath.Join(collectionsDir, namespace.Name(), collection.Name(), "roles")
			collectRoleSpecs(rolesDir, namespace.Name()+"."+collection.Name(), roles)
		}
	}
	return roles
}

// collectRoleSpecs reads one roles directory's argument specs into roles;
// unparseable specs narrate to the log and skip (zoneweaver's tolerance).
func collectRoleSpecs(rolesDir, collectionID string, roles map[string]RoleSpec) {
	entries, err := os.ReadDir(rolesDir)
	if err != nil {
		return
	}
	for _, role := range entries {
		if !role.IsDir() {
			continue
		}
		specFile := filepath.Join(rolesDir, role.Name(), "meta", "argument_specs.yml")
		raw, rerr := os.ReadFile(filepath.Clean(specFile))
		if rerr != nil {
			continue
		}
		doc := struct {
			ArgumentSpecs map[string]struct {
				ShortDescription string         `yaml:"short_description"`
				Options          map[string]any `yaml:"options"`
			} `yaml:"argument_specs"`
		}{}
		if uerr := yaml.Unmarshal(raw, &doc); uerr != nil {
			plog().Warn("skipping unparseable argument_specs", "role", role.Name(), "error", uerr)
			continue
		}
		main, ok := doc.ArgumentSpecs["main"]
		if !ok {
			continue
		}
		options := main.Options
		if options == nil {
			options = map[string]any{}
		}
		roles[role.Name()] = RoleSpec{
			Collection:       collectionID,
			ShortDescription: main.ShortDescription,
			Options:          options,
		}
	}
}

// BuildRoleSpecs (re)builds a version's role-specs.yml from the shipped
// specs; a version with no specs loses any stale cache. Returns the cached
// role count.
func BuildRoleSpecs(versionRoot string) (int, error) {
	roles := deriveRoleSpecs(versionRoot)
	file := filepath.Join(versionRoot, roleSpecsFile)
	if len(roles) == 0 {
		if rerr := os.Remove(file); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return 0, rerr
		}
		return 0, nil
	}
	raw, err := yaml.Marshal(&RoleSpecs{Roles: roles})
	if err != nil {
		return 0, err
	}
	if werr := safepath.WriteFile(file, raw, 0o644); werr != nil {
		return 0, werr
	}
	return len(roles), nil
}

// ReadRoleSpecs reads a version's cache, building a missing one on the spot
// (hand-dropped packages). nil when the package ships no specs.
func ReadRoleSpecs(versionRoot string) *RoleSpecs {
	file := filepath.Join(versionRoot, roleSpecsFile)
	raw, err := os.ReadFile(filepath.Clean(file))
	if errors.Is(err, fs.ErrNotExist) {
		count, berr := BuildRoleSpecs(versionRoot)
		if berr != nil {
			plog().Warn("role-specs build failed", "root", versionRoot, "error", berr)
			return nil
		}
		if count == 0 {
			return nil
		}
		raw, err = os.ReadFile(filepath.Clean(file))
	}
	if err != nil {
		plog().Warn("unreadable role-specs cache", "file", file, "error", err)
		return nil
	}
	specs := &RoleSpecs{}
	if uerr := yaml.Unmarshal(raw, specs); uerr != nil {
		plog().Warn("unreadable role-specs cache", "file", file, "error", uerr)
		return nil
	}
	return specs
}

// RefreshAllRoleSpecs re-derives every registry version's cache — the manual
// refresh for hand-dropped packages and updated specs (imports rebuild
// automatically).
func (r *Registry) RefreshAllRoleSpecs() ([]RefreshedSpecs, error) {
	collections, err := r.List()
	if err != nil {
		return nil, err
	}
	refreshed := []RefreshedSpecs{}
	for _, collection := range collections {
		for _, entry := range collection.Versions {
			count, berr := BuildRoleSpecs(entry.Root)
			if berr != nil {
				plog().Warn("role-specs rebuild failed",
					"name", collection.Name, "version", entry.Version, "error", berr)
			}
			refreshed = append(refreshed, RefreshedSpecs{
				Name: collection.Name, Version: entry.Version, Roles: count,
			})
		}
	}
	return refreshed, nil
}
