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

// Collection is one provisioner family on disk. name is the registry
// directory name — the stable identity URLs address; the manifest's own
// display fields ride in Metadata verbatim.
type Collection struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// false marks a family with no parseable versions (SHI's invalid placeholder) — still listed, still deletable
	Valid bool `json:"valid"`
	// provisioner-collection.yml, verbatim
	Metadata map[string]any `json:"metadata"`
	// Newest first
	Versions []*Version `json:"versions"`
	// Stored git provenance — recorded at git import, NEVER inside package files: {source_type: "git", url, branch?}. null for folder/archive imports and catalog installs (catalog families update through the catalog). Feeds POST /provisioning/provisioners/{name}/refresh-from-source.
	Source *Source `json:"source"`
}

// Version is one provisioner package version. metadata is the full
// provisioner.yml — metadata.roles plus the Field DSL (metadata.configuration
// = {groups, fields}, design §3.1: the closed 12-type set, ordered groups
// with an advanced toggle, the closed show_if grammar, validate blocks) drive
// the machine-create forms; metadata.presentation and metadata.forked_from
// ride through verbatim. Imports LINT the DSL fail-closed (unknown type =
// refusal listing every problem) and derive schema.json (JSON Schema 2020-12)
// beside role-specs.yml. The VERSION-DETAIL read additionally carries
// role_specs (Mark's argument-specs ruling 2026-07-12, shared wire with
// zoneweaver): every shipped role's meta/argument_specs.yml folded into
// role_specs.roles[<name>] = {collection, short_description, options} —
// derived into a role-specs.yml cache beside provisioner.yml at import
// (self-healing at read for hand-dropped packages; POST
// /provisioning/provisioners/refresh-specs re-derives everything). The UI
// builds its per-role knob FORMS from options; absent when the package ships
// no specs.
type Version struct {
	// The manifest's version field (falls back to the directory name)
	Version string `json:"version"`
	// Version directory name — the URL segment
	Dir         string `json:"dir"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Absolute path of the version directory on the agent host
	Root string `json:"root"`
	// provisioner.yml, verbatim
	Metadata map[string]any `json:"metadata"`
	// Version-detail read only: {roles: {<role>: {collection, short_description, options}}} — the cached argument specs; absent in listings and when the package ships none
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
