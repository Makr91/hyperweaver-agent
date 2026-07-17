// Package provisioner implements the provisioner package registry (design
// §5, SHI's ProvisionerManager model): packages in SHI's on-disk format —
// <provisioners dir>/<name>/provisioner-collection.yml with
// <version>/provisioner.yml trees beneath — discovered by scanning, seeded
// from installer-shipped archives without ever clobbering existing versions,
// imported from local folders, archives, or git clones, and deleted only
// while no machine references them. One system for every package family
// (Mark's ruling): the HCL bundles are just packages with rich metadata,
// never special-cased by name.
package provisioner

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
)

// plog is this package's category logger (logging.categories.provisioning
// overrides its level).
func plog() *slog.Logger {
	return logging.Category("provisioning")
}

// The two manifest files of SHI's package format: one names the family, one
// names each version.
const (
	collectionManifest = "provisioner-collection.yml"
	versionManifest    = "provisioner.yml"
)

// sourceFileName is a family's import-provenance sidecar, beside its
// collection manifest. Dot-prefixed on purpose: ValidName rejects dot-led
// entries, so registry scans skip it, and share archives (version-tree only)
// never carry it — provenance is registry-side state, never package content
// (converged with zoneweaver, sync 2026-07-17).
const sourceFileName = ".source.json"

// Source is a family's import provenance — recorded by git imports only.
// TokenName NAMES a git_api_keys entry in the global secrets store (Mark's
// private-repo ruling 2026-07-17: private repos ARE refreshable) — the token
// itself never lands in provenance; refresh-from-source resolves it from the
// secrets store at RUN time, exactly like the original import.
// Folder/archive/catalog imports record nothing.
type Source struct {
	SourceType string `json:"source_type"`
	URL        string `json:"url"`
	Branch     string `json:"branch,omitempty"`
	TokenName  string `json:"token_name,omitempty"`
}

// namePattern accepts provisioner family and version directory names,
// rejecting path- and shell-hostile input (and dot-prefixed entries) before
// any filesystem use.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidName reports whether s is acceptable as a provisioner family or
// version directory name.
func ValidName(s string) bool {
	return namePattern.MatchString(s)
}

// Collection is one provisioner family on disk. Name is the directory name —
// the stable identity URLs address; the manifest's own display fields ride in
// Metadata verbatim.
type Collection struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Valid       bool           `json:"valid"`
	Metadata    map[string]any `json:"metadata"`
	Versions    []*Version     `json:"versions"`
	// Source is the family's git-import provenance (.source.json) — JSON
	// null, never absent, for families without one (list AND detail expose
	// it; the converged wire shape).
	Source *Source `json:"source"`
}

// Version is one package version. Metadata is the full provisioner.yml —
// metadata.roles and configuration.basicFields/advancedFields drive the UI
// forms exactly as in SHI's custom-provisioner stack. Dir is the version
// directory name (the URL segment); Version is the manifest's version field,
// falling back to Dir.
type Version struct {
	Version     string         `json:"version"`
	Dir         string         `json:"dir"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Root        string         `json:"root"`
	Metadata    map[string]any `json:"metadata"`
	// RoleSpecs is the derived per-role argument-spec cache — attached on
	// the version-detail read only (GetVersion), never in listings.
	RoleSpecs *RoleSpecs `json:"role_specs,omitempty"`
}

// readManifest parses one YAML manifest into a generic document (served to
// the UI verbatim as JSON).
func readManifest(path string) (map[string]any, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return doc, nil
}

// metaString extracts a string field from a manifest document ("" when
// absent or not a string).
func metaString(doc map[string]any, key string) string {
	if doc == nil {
		return ""
	}
	s, _ := doc[key].(string)
	return s
}
