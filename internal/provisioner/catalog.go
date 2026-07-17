package provisioner

// The public-catalog client (design §7 — the HACS model; the Catalog AI's
// live wire, 2026-07-17): fetch catalog.json from configured sources
// (catalog_sources mirrors the template-sources pattern; second-door forks
// are just more sources), gate on format_version 1, download the immutable
// VERSIONED asset, verify its sha256, then feed the ordinary import path —
// the same lint gate and non-clobber rules every import gets. Artifact URLs
// are OPAQUE (release tags carry slashes — never parse or construct them).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// OpCatalogInstall is the catalog-install task operation (CategorySystem —
// it ends in a registry write, serialized with imports).
const OpCatalogInstall = "provisioner_catalog_install"

// catalogFormatVersion is the ONE format this client speaks.
const catalogFormatVersion = 1

// catalogFetchTimeout bounds the catalog.json fetch; downloads get
// catalogDownloadTimeout (assets are tens of MB, the document is KB).
const (
	catalogFetchTimeout    = 60 * time.Second
	catalogDownloadTimeout = 3600 * time.Second
)

// CatalogSource is one configured catalog (config catalog_sources[]).
type CatalogSource struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	Default bool   `json:"default"`
	CAFile  string `json:"-"`
}

// CatalogArtifact is one downloadable asset of a catalog version.
type CatalogArtifact struct {
	URL          string `json:"url"`
	ChecksumType string `json:"checksum_type"`
	Checksum     string `json:"checksum"`
}

// CatalogVersion is one published version (semver-DESC in the document).
type CatalogVersion struct {
	Version   string            `json:"version"`
	Artifacts []CatalogArtifact `json:"artifacts"`
}

// CatalogFamily is one admitted provisioner family.
type CatalogFamily struct {
	Name        string           `json:"name"`
	Repo        string           `json:"repo"`
	Description string           `json:"description"`
	Versions    []CatalogVersion `json:"versions"`
}

// CatalogDocument is catalog.json.
type CatalogDocument struct {
	Name          string          `json:"name"`
	FormatVersion int             `json:"format_version"`
	Updated       string          `json:"updated"`
	Provisioners  []CatalogFamily `json:"provisioners"`
}

// FindCatalogSource picks a source by name, or the default when name is
// empty. Disabled sources never match.
func FindCatalogSource(sources []CatalogSource, name string) (*CatalogSource, error) {
	for i := range sources {
		if !sources[i].Enabled {
			continue
		}
		if name != "" && sources[i].Name == name {
			return &sources[i], nil
		}
		if name == "" && sources[i].Default {
			return &sources[i], nil
		}
	}
	if name != "" {
		return nil, errors.New("no enabled catalog source named " + name)
	}
	return nil, errors.New("no enabled default catalog source is configured")
}

// catalogClient builds the HTTP client for one source: certificate
// verification always on, with the source's CA bundle appended for
// self-hosted forks (the template-sources ca_file pattern).
func catalogClient(source *CatalogSource, timeout time.Duration) (*http.Client, error) {
	client := &http.Client{Timeout: timeout}
	if source.CAFile == "" {
		return client, nil
	}
	clean, err := safepath.CleanAbs(source.CAFile)
	if err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(filepath.Clean(clean))
	if err != nil {
		return nil, fmt.Errorf("read catalog CA bundle: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("catalog CA bundle carries no usable PEM certificates")
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}
	return client, nil
}

// FetchCatalog downloads and validates one source's catalog.json: HTTP 200,
// parseable JSON, format_version exactly 1 (the consumption contract's gate).
func FetchCatalog(ctx context.Context, source *CatalogSource) (*CatalogDocument, error) {
	client, err := catalogClient(source, catalogFetchTimeout)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, http.NoBody)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch catalog %s: %w", source.Name, err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog %s answered HTTP %d", source.Name, response.StatusCode)
	}

	document := &CatalogDocument{}
	if derr := json.NewDecoder(response.Body).Decode(document); derr != nil {
		return nil, fmt.Errorf("parse catalog %s: %w", source.Name, derr)
	}
	if document.FormatVersion != catalogFormatVersion {
		return nil, fmt.Errorf("catalog %s is format_version %d — this agent speaks %d",
			source.Name, document.FormatVersion, catalogFormatVersion)
	}
	return document, nil
}

// CatalogInstallMetadata is the provisioner_catalog_install task's metadata.
// The artifact URL and checksum resolve AT RUN TIME from a fresh catalog
// fetch — versions may disappear between fetches (a deleted release), and a
// stale pinned URL would 404 anyway; published checksums never change.
type CatalogInstallMetadata struct {
	SourceName string `json:"source_name,omitempty"`
	Name       string `json:"name"`
	Version    string `json:"version"`
}

// catalogInstall executes provisioner_catalog_install: fetch → resolve →
// download the VERSIONED asset → verify sha256 → the ordinary import path
// (lint gate, non-clobber, role-specs + schema derivation included).
func (e *executors) catalogInstall(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if task.Metadata == nil {
		return errors.New("catalog install task has no metadata")
	}
	var meta CatalogInstallMetadata
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse catalog install metadata: %w", err)
	}
	source, err := FindCatalogSource(e.catalogSources, meta.SourceName)
	if err != nil {
		return err
	}

	out.Write("stdout", "Fetching catalog "+source.Name+"\n")
	document, err := FetchCatalog(ctx, source)
	if err != nil {
		return err
	}
	artifact, err := resolveCatalogArtifact(document, meta.Name, meta.Version)
	if err != nil {
		return err
	}

	parsed, err := url.Parse(artifact.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("catalog artifact URL is not an http(s) URL")
	}
	filename := path.Base(parsed.Path)
	if !isArchive(filename) {
		return fmt.Errorf("catalog artifact %q does not name a supported archive (.tar.gz/.tgz/.zip)", filename)
	}

	temp, err := os.MkdirTemp("", "hyperweaver-catalog-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = removeAllForce(temp)
	}()
	archivePath := filepath.Join(temp, filename)

	out.Write("stdout", "Downloading "+artifact.URL+"\n")
	sum, size, err := downloadVerified(ctx, source, artifact.URL, archivePath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, artifact.Checksum) {
		return fmt.Errorf("checksum MISMATCH for %s: downloaded %s, catalog pins %s — refusing to import",
			filename, sum, artifact.Checksum)
	}
	out.Write("stdout", fmt.Sprintf("Verified sha256 %s (%d bytes)\n", sum, size))

	return e.runImport(ctx, &ImportMetadata{SourceType: SourceArchive, Path: archivePath}, out)
}

// resolveCatalogArtifact finds the named family+version's sha256 artifact.
func resolveCatalogArtifact(document *CatalogDocument, name, version string) (*CatalogArtifact, error) {
	for i := range document.Provisioners {
		if document.Provisioners[i].Name != name {
			continue
		}
		for j := range document.Provisioners[i].Versions {
			entry := &document.Provisioners[i].Versions[j]
			if entry.Version != version {
				continue
			}
			for k := range entry.Artifacts {
				artifact := &entry.Artifacts[k]
				if strings.EqualFold(artifact.ChecksumType, "sha256") &&
					artifact.URL != "" && artifact.Checksum != "" {
					return artifact, nil
				}
			}
			return nil, fmt.Errorf("%s %s carries no sha256-checksummed artifact", name, version)
		}
		return nil, fmt.Errorf("%s has no version %s in the catalog (versions may disappear when an author deletes a release)", name, version)
	}
	return nil, errors.New(name + " is not in the catalog")
}

// downloadVerified streams one asset to dest, hashing the bytes as they land.
func downloadVerified(ctx context.Context, source *CatalogSource, assetURL, dest string) (sum string, size int64, err error) {
	client, err := catalogClient(source, catalogDownloadTimeout)
	if err != nil {
		return "", 0, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, http.NoBody)
	if err != nil {
		return "", 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", 0, fmt.Errorf("download asset: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("asset download answered HTTP %d", response.StatusCode)
	}

	hasher := sha256.New()
	size, err = safepath.WriteFileFrom(dest, io.TeeReader(response.Body, hasher), 0o600)
	if err != nil {
		return "", size, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}
