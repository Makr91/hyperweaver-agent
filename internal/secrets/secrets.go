// Package secrets implements the agent's global secrets store (architecture
// D-C, SHI's SuperHumanSecrets model): six repeatable categories persisted
// to secrets.yaml beside the config file, 0600, served by an admin-only
// API — a store of its own purely so GET /settings keeps serving just the
// configuration document. Values are plain text BY DESIGN (Mark's ruling):
// it is the user's local machine, and the generated Hosts.yml carries them
// as SECRETS_* template vars anyway. Independently of these vars, Hosts.rb
// merges the working copy's secrets.yml/.secrets.yml at vagrant runtime —
// that mechanism coexists and is never touched by this store.
package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// namePattern is SHI's SecretsPage name rule, minus its empty-string
// allowance: entries must be addressable.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// NamedKey is one name→key credential (HCL portal keys, git API keys, Atlas
// tokens, SSH private keys).
type NamedKey struct {
	Name string `yaml:"name" json:"name"`
	Key  string `yaml:"key"  json:"key"`
}

// CustomResourceURL is one download mirror, optionally HTTP-Basic-guarded.
type CustomResourceURL struct {
	Name    string `yaml:"name"    json:"name"`
	URL     string `yaml:"url"     json:"url"`
	UseAuth bool   `yaml:"useAuth" json:"useAuth"`
	User    string `yaml:"user"    json:"user"`
	Pass    string `yaml:"pass"    json:"pass"`
}

// DockerHub is one Docker Hub credential pair.
type DockerHub struct {
	Name           string `yaml:"name"             json:"name"`
	DockerHubUser  string `yaml:"docker_hub_user"  json:"docker_hub_user"`
	DockerHubToken string `yaml:"docker_hub_token" json:"docker_hub_token"`
}

// Document is the whole secrets file — SHI's six category names, verbatim.
type Document struct {
	HCLDownloadPortalAPIKeys []NamedKey          `yaml:"hcl_download_portal_api_keys" json:"hcl_download_portal_api_keys"`
	GitAPIKeys               []NamedKey          `yaml:"git_api_keys"                 json:"git_api_keys"`
	VagrantAtlasToken        []NamedKey          `yaml:"vagrant_atlas_token"          json:"vagrant_atlas_token"`
	CustomResourceURL        []CustomResourceURL `yaml:"custom_resource_url"          json:"custom_resource_url"`
	DockerHub                []DockerHub         `yaml:"docker_hub"                   json:"docker_hub"`
	SSHKeys                  []NamedKey          `yaml:"ssh_keys"                     json:"ssh_keys"`
}

// emptyDocument returns a Document whose slices are non-nil, so the API
// serves [] for empty categories instead of null.
func emptyDocument() Document {
	return Document{
		HCLDownloadPortalAPIKeys: []NamedKey{},
		GitAPIKeys:               []NamedKey{},
		VagrantAtlasToken:        []NamedKey{},
		CustomResourceURL:        []CustomResourceURL{},
		DockerHub:                []DockerHub{},
		SSHKeys:                  []NamedKey{},
	}
}

// Store persists the secrets document.
type Store struct {
	path string

	mu  sync.Mutex
	doc Document
}

// Open loads the store from path; a missing file is an empty store.
func Open(path string) (*Store, error) {
	clean, err := safepath.CleanAbs(path)
	if err != nil {
		return nil, err
	}
	s := &Store{path: clean, doc: emptyDocument()}

	raw, err := os.ReadFile(filepath.Clean(clean))
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secrets store: %w", err)
	}
	if uerr := yaml.Unmarshal(raw, &s.doc); uerr != nil {
		return nil, fmt.Errorf("parse secrets store %s: %w", clean, uerr)
	}
	normalize(&s.doc)
	return s, nil
}

// normalize keeps every category slice non-nil after unmarshaling.
func normalize(doc *Document) {
	empty := emptyDocument()
	if doc.HCLDownloadPortalAPIKeys == nil {
		doc.HCLDownloadPortalAPIKeys = empty.HCLDownloadPortalAPIKeys
	}
	if doc.GitAPIKeys == nil {
		doc.GitAPIKeys = empty.GitAPIKeys
	}
	if doc.VagrantAtlasToken == nil {
		doc.VagrantAtlasToken = empty.VagrantAtlasToken
	}
	if doc.CustomResourceURL == nil {
		doc.CustomResourceURL = empty.CustomResourceURL
	}
	if doc.DockerHub == nil {
		doc.DockerHub = empty.DockerHub
	}
	if doc.SSHKeys == nil {
		doc.SSHKeys = empty.SSHKeys
	}
}

// Get returns a copy of the document.
func (s *Store) Get() Document {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyDocument(&s.doc)
}

func copyDocument(doc *Document) Document {
	out := *doc
	out.HCLDownloadPortalAPIKeys = append([]NamedKey{}, doc.HCLDownloadPortalAPIKeys...)
	out.GitAPIKeys = append([]NamedKey{}, doc.GitAPIKeys...)
	out.VagrantAtlasToken = append([]NamedKey{}, doc.VagrantAtlasToken...)
	out.CustomResourceURL = append([]CustomResourceURL{}, doc.CustomResourceURL...)
	out.DockerHub = append([]DockerHub{}, doc.DockerHub...)
	out.SSHKeys = append([]NamedKey{}, doc.SSHKeys...)
	return out
}

// Replace overwrites the submitted categories (PUT /secrets semantics — the
// same top-level shallow merge the settings surface uses) and persists the
// result. Unknown categories and invalid entry names are rejected whole; the
// store never half-applies.
func (s *Store) Replace(categories map[string]json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := copyDocument(&s.doc)
	for category, raw := range categories {
		if err := applyCategory(&updated, category, raw); err != nil {
			return err
		}
	}
	if err := validate(&updated); err != nil {
		return err
	}

	data, err := yaml.Marshal(&updated)
	if err != nil {
		return fmt.Errorf("serialize secrets: %w", err)
	}
	if werr := safepath.WriteFile(s.path, data, 0o600); werr != nil {
		return fmt.Errorf("write secrets store: %w", werr)
	}
	s.doc = updated
	return nil
}

// applyCategory unmarshals one submitted category into its slot.
func applyCategory(doc *Document, category string, raw json.RawMessage) error {
	var err error
	switch category {
	case "hcl_download_portal_api_keys":
		err = json.Unmarshal(raw, &doc.HCLDownloadPortalAPIKeys)
	case "git_api_keys":
		err = json.Unmarshal(raw, &doc.GitAPIKeys)
	case "vagrant_atlas_token":
		err = json.Unmarshal(raw, &doc.VagrantAtlasToken)
	case "custom_resource_url":
		err = json.Unmarshal(raw, &doc.CustomResourceURL)
	case "docker_hub":
		err = json.Unmarshal(raw, &doc.DockerHub)
	case "ssh_keys":
		err = json.Unmarshal(raw, &doc.SSHKeys)
	default:
		return errors.New("unknown secrets category: " + category)
	}
	if err != nil {
		return fmt.Errorf("category %s: %w", category, err)
	}
	normalize(doc)
	return nil
}

// validate checks every entry name (SHI's ^[a-zA-Z0-9_-]*$ rule, non-empty).
func validate(doc *Document) error {
	check := func(category, name string) error {
		if !namePattern.MatchString(name) {
			return fmt.Errorf("category %s: name %q must match [a-zA-Z0-9_-]+", category, name)
		}
		return nil
	}
	for _, entry := range doc.HCLDownloadPortalAPIKeys {
		if err := check("hcl_download_portal_api_keys", entry.Name); err != nil {
			return err
		}
	}
	for _, entry := range doc.GitAPIKeys {
		if err := check("git_api_keys", entry.Name); err != nil {
			return err
		}
	}
	for _, entry := range doc.VagrantAtlasToken {
		if err := check("vagrant_atlas_token", entry.Name); err != nil {
			return err
		}
	}
	for _, entry := range doc.CustomResourceURL {
		if err := check("custom_resource_url", entry.Name); err != nil {
			return err
		}
	}
	for _, entry := range doc.DockerHub {
		if err := check("docker_hub", entry.Name); err != nil {
			return err
		}
	}
	for _, entry := range doc.SSHKeys {
		if err := check("ssh_keys", entry.Name); err != nil {
			return err
		}
	}
	return nil
}

// HCLToken returns the named HCL download-portal refresh token.
func (s *Store) HCLToken(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.doc.HCLDownloadPortalAPIKeys {
		if entry.Name == name {
			return entry.Key, entry.Key != ""
		}
	}
	return "", false
}

// UpdateHCLToken persists a rotated HCL refresh token in place — the portal
// rotates the token on EVERY exchange, and losing the rotation breaks the
// next run (SHI's critical rule: the rotated token is written back
// immediately).
func (s *Store) UpdateHCLToken(name, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.doc.HCLDownloadPortalAPIKeys {
		if s.doc.HCLDownloadPortalAPIKeys[i].Name != name {
			continue
		}
		updated := copyDocument(&s.doc)
		updated.HCLDownloadPortalAPIKeys[i].Key = token
		data, err := yaml.Marshal(&updated)
		if err != nil {
			return fmt.Errorf("serialize secrets: %w", err)
		}
		if werr := safepath.WriteFile(s.path, data, 0o600); werr != nil {
			return fmt.Errorf("write secrets store: %w", werr)
		}
		s.doc = updated
		return nil
	}
	return errors.New("no hcl_download_portal_api_keys entry named " + name)
}

// ResourceAuth returns the named custom_resource_url entry's Basic-auth
// pair — the artifact downloader's credential lookup (SHI's
// downloadFileWithCustomResource). ok is false when the entry is absent or
// carries no auth.
func (s *Store) ResourceAuth(name string) (user, pass string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.doc.CustomResourceURL {
		if entry.Name == name {
			if !entry.UseAuth {
				return "", "", false
			}
			return entry.User, entry.Pass, true
		}
	}
	return "", "", false
}

// GitToken returns the named git API key ("" when absent) — the private-repo
// credential for provisioner git imports.
func (s *Store) GitToken(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.doc.GitAPIKeys {
		if entry.Name == name {
			return entry.Key
		}
	}
	return ""
}

// TemplateVars derives the SECRETS_* template variables injected into the
// generated Hosts.yml (SHI §2.2 semantics: every category's entries become
// per-name vars, names sanitized uppercase with hyphens as underscores;
// plain text by design).
func (s *Store) TemplateVars() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	vars := map[string]string{}
	for _, entry := range s.doc.HCLDownloadPortalAPIKeys {
		vars["SECRETS_"+sanitizeVarName(entry.Name)] = entry.Key
	}
	for _, entry := range s.doc.GitAPIKeys {
		vars["SECRETS_"+sanitizeVarName(entry.Name)] = entry.Key
	}
	for _, entry := range s.doc.VagrantAtlasToken {
		vars["SECRETS_"+sanitizeVarName(entry.Name)] = entry.Key
	}
	for _, entry := range s.doc.CustomResourceURL {
		prefix := "SECRETS_" + sanitizeVarName(entry.Name)
		vars[prefix+"_URL"] = entry.URL
		if entry.UseAuth {
			vars[prefix+"_USER"] = entry.User
			vars[prefix+"_PASS"] = entry.Pass
		}
	}
	for _, entry := range s.doc.DockerHub {
		prefix := "SECRETS_" + sanitizeVarName(entry.Name)
		vars[prefix+"_USER"] = entry.DockerHubUser
		vars[prefix+"_TOKEN"] = entry.DockerHubToken
	}
	for _, entry := range s.doc.SSHKeys {
		vars["SECRETS_"+sanitizeVarName(entry.Name)+"_SSH"] = entry.Key
	}
	return vars
}

// sanitizeVarName uppercases a secret name into template-variable form.
func sanitizeVarName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}
