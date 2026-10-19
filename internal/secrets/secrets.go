// Package secrets reads the secret rows of the vault store for the agent's own consumers, the HCL portal keys, a custom resource's credentials, git tokens and the SECRETS_* template variables, and moves the entries of the old secrets.yaml into rows once.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Makr91/hyperweaver-agent/internal/certs"
)

const lookupTimeout = 10 * time.Second

// ImportCreatedBy is the creator the imported rows carry.
const ImportCreatedBy = "system"

// Store reads secret rows by kind and name.
type Store struct {
	certs *certs.Store
}

// New wraps the vault store.
func New(store *certs.Store) *Store {
	return &Store{certs: store}
}

func (s *Store) row(kind, name string) (*certs.Row, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	row, err := s.certs.FindByName(ctx, kind, name)
	return row, err == nil
}

// HCLToken answers the named api_key row's key, the HCL download portal's refresh token.
func (s *Store) HCLToken(name string) (string, bool) {
	row, ok := s.row(certs.KindAPIKey, name)
	if !ok {
		return "", false
	}
	key := certs.SecretValue(row)
	return key, key != ""
}

// UpdateHCLToken persists the rotated refresh token onto the named api_key row.
func (s *Store) UpdateHCLToken(name, token string) error {
	row, ok := s.row(certs.KindAPIKey, name)
	if !ok {
		return errors.New("no api_key secret named " + name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	return s.certs.SetSecretMember(ctx, row.ID, "key", token)
}

// ResourceAuth answers the named basic_auth row's user and password; ok is false when the row is absent or names no user.
func (s *Store) ResourceAuth(name string) (user, pass string, ok bool) {
	row, found := s.row(certs.KindBasicAuth, name)
	if !found {
		return "", "", false
	}
	secret := certs.Secret(row)
	user, _ = secret["user"].(string)
	pass, _ = secret["password"].(string)
	return user, pass, user != ""
}

// GitToken answers the named api_key row's key, empty when absent.
func (s *Store) GitToken(name string) string {
	row, ok := s.row(certs.KindAPIKey, name)
	if !ok {
		return ""
	}
	return certs.SecretValue(row)
}

// FirstAPIKey answers the name of the newest api_key row the persons may reach, empty when none.
func (s *Store) FirstAPIKey(persons []string) string {
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	rows, err := s.certs.List(ctx, certs.Reader{Persons: persons}, certs.KindAPIKey, "")
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0].Name
}

// TemplateVars answers the SECRETS_* variables of every secret row the persons may reach: SECRETS_<NAME> holding the row's first member, and SECRETS_<NAME>_<MEMBER> for every other string member of its secret and every member of its extra.
func (s *Store) TemplateVars(persons []string) map[string]string {
	vars := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	rows, err := s.certs.List(ctx, certs.Reader{Persons: persons}, "", "")
	if err != nil {
		return vars
	}
	for _, row := range rows {
		if !certs.SecretKinds[row.Kind] {
			continue
		}
		prefix := "SECRETS_" + sanitizeVarName(row.Name)
		first := certs.FirstMember(row.Kind)
		if value := certs.SecretValue(row); value != "" {
			vars[prefix] = value
		}
		for member, value := range certs.Secret(row) {
			if text, isText := value.(string); isText && member != first {
				vars[prefix+"_"+sanitizeVarName(member)] = text
			}
		}
		for member, value := range certs.Extra(row) {
			vars[prefix+"_"+sanitizeVarName(member)] = value
		}
	}
	return vars
}

func sanitizeVarName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

type legacyKey struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

type legacyResource struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	UseAuth bool   `yaml:"useAuth"`
	User    string `yaml:"user"`
	Pass    string `yaml:"pass"`
}

type legacyDockerHub struct {
	Name           string `yaml:"name"`
	DockerHubUser  string `yaml:"docker_hub_user"`
	DockerHubToken string `yaml:"docker_hub_token"`
}

type legacyDocument struct {
	HCLDownloadPortalAPIKeys []legacyKey       `yaml:"hcl_download_portal_api_keys"`
	GitAPIKeys               []legacyKey       `yaml:"git_api_keys"`
	VagrantAtlasToken        []legacyKey       `yaml:"vagrant_atlas_token"`
	CustomResourceURL        []legacyResource  `yaml:"custom_resource_url"`
	DockerHub                []legacyDockerHub `yaml:"docker_hub"`
	SSHKeys                  []legacyKey       `yaml:"ssh_keys"`
}

// Import moves the entries of the old secrets.yaml at path into rows, each published and created by the host's own account, and removes the file; a missing file is nothing to do. It answers how many rows were made.
func (s *Store) Import(ctx context.Context, path string) (int, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	var doc legacyDocument
	if uerr := yaml.Unmarshal(raw, &doc); uerr != nil {
		return 0, fmt.Errorf("parse %s: %w", path, uerr)
	}
	count := 0
	add := func(kind, name string, secret map[string]any) error {
		if name == "" {
			return nil
		}
		_, cerr := s.certs.Create(ctx, ImportCreatedBy, &certs.Write{
			Kind: kind, Name: name, Published: true,
			Record: map[string]any{"kind": kind, "name": name, "secret": secret},
		})
		if cerr != nil {
			return cerr
		}
		count++
		return nil
	}
	apiKeys := append(append(append([]legacyKey{}, doc.HCLDownloadPortalAPIKeys...), doc.GitAPIKeys...), doc.VagrantAtlasToken...)
	for _, entry := range apiKeys {
		if aerr := add(certs.KindAPIKey, entry.Name, map[string]any{"key": entry.Key, "url": "", "account_id": ""}); aerr != nil {
			return count, aerr
		}
	}
	for _, entry := range doc.CustomResourceURL {
		secret := map[string]any{"url": entry.URL, "user": "", "password": ""}
		if entry.UseAuth {
			secret["user"] = entry.User
			secret["password"] = entry.Pass
		}
		if aerr := add(certs.KindBasicAuth, entry.Name, secret); aerr != nil {
			return count, aerr
		}
	}
	for _, entry := range doc.DockerHub {
		secret := map[string]any{"url": "https://hub.docker.com", "user": entry.DockerHubUser, "password": entry.DockerHubToken}
		if aerr := add(certs.KindBasicAuth, entry.Name, secret); aerr != nil {
			return count, aerr
		}
	}
	for _, entry := range doc.SSHKeys {
		if aerr := add(certs.KindSSHKey, entry.Name, map[string]any{"private_key": entry.Key, "public_key": "", "passphrase": ""}); aerr != nil {
			return count, aerr
		}
	}
	if rerr := os.Remove(path); rerr != nil {
		return count, fmt.Errorf("remove %s: %w", path, rerr)
	}
	return count, nil
}
