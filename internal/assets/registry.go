package assets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// OpRegistryDownload is the task that fetches one download file of a box registry into a location.
const OpRegistryDownload = "artifact_registry_download"

// ErrRegistryAuth is answered when the registry refuses the credential sent.
var ErrRegistryAuth = errors.New("the registry refused the credential")

// RegistryFetch sends one GET to the enabled box registry sourceID names at path, as the person the key createdBy stands for under the registry ladder; the caller closes the body.
type RegistryFetch func(ctx context.Context, sourceID, createdBy, path string) (*http.Response, error)

// RegistryDownloadMetadata is the artifact_registry_download task's metadata document.
type RegistryDownloadMetadata struct {
	SourceName   string `json:"source_name"`
	Organization string `json:"organization"`
	Download     string `json:"download"`
	Release      string `json:"release"`
	Patch        string `json:"patch"`
	Filename     string `json:"filename"`
	Kind         string `json:"kind"`
	Role         string `json:"role"`
	// LocationID names the location the file lands in; empty selects the kind's default location
	LocationID        string `json:"storage_path_id,omitempty"`
	Checksum          string `json:"checksum,omitempty"`
	ChecksumAlgorithm string `json:"checksum_algorithm,omitempty"`
	OverwriteExisting bool   `json:"overwrite_existing,omitempty"`
}

// Validate checks a registry download request before it becomes a task.
func (m *RegistryDownloadMetadata) Validate() error {
	required := []struct{ name, value string }{
		{"source_name", m.SourceName},
		{"organization", m.Organization},
		{"download", m.Download},
		{"release", m.Release},
		{"patch", m.Patch},
		{"filename", m.Filename},
		{"kind", m.Kind},
		{"role", m.Role},
	}
	for _, member := range required {
		if member.value == "" {
			return errors.New(member.name + " is required")
		}
	}
	m.Kind = NormalizeKind(m.Kind)
	if !RoleKeyed(m.Kind) {
		return errors.New("kind must be installer, fixpack, or hotfix")
	}
	if !ValidRole(m.Role) {
		return errors.New("role is not usable")
	}
	if !ValidFilename(m.Filename) {
		return errors.New("filename is not usable")
	}
	m.ChecksumAlgorithm = NormalizeAlgorithm(m.ChecksumAlgorithm)
	return ValidateChecksum(m.Checksum, m.ChecksumAlgorithm)
}

// FilePath answers the registry path of the file the metadata names.
func (m *RegistryDownloadMetadata) FilePath() string {
	return "/api/organization/" + url.PathEscape(m.Organization) +
		"/download/" + url.PathEscape(m.Download) +
		"/release/" + url.PathEscape(m.Release) +
		"/patch/" + url.PathEscape(m.Patch) +
		"/file/" + url.PathEscape(m.Filename) + "/download"
}

// ParseRegistryFileURL reads the organization, download, release, patch and file a registry file download URL names; false for any other URL.
func ParseRegistryFileURL(rawURL string) (meta RegistryDownloadMetadata, ok bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return meta, false
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) != 12 || segments[0] != "api" || segments[1] != "organization" ||
		segments[3] != "download" || segments[5] != "release" || segments[7] != "patch" ||
		segments[9] != "file" || segments[11] != "download" {
		return meta, false
	}
	meta.Organization = segments[2]
	meta.Download = segments[4]
	meta.Release = segments[6]
	meta.Patch = segments[8]
	meta.Filename = segments[10]
	return meta, true
}

// registryDownload executes one artifact_registry_download task: fetch the file from the registry as the person who queued it, stream it into the location under the role, verify the given checksum, register the row.
func (e *executors) registryDownload(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta RegistryDownloadMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	if err := meta.Validate(); err != nil {
		return err
	}
	if e.deps.RegistryFetch == nil {
		return errors.New("no box registries are configured")
	}
	location, err := e.kindLocation(ctx, meta.Kind, meta.LocationID)
	if err != nil {
		return err
	}
	target, err := PathFor(location, meta.Role, meta.Filename)
	if err != nil {
		return err
	}
	if !meta.OverwriteExisting {
		if _, serr := os.Stat(target); serr == nil {
			return fmt.Errorf("file already exists: %s (set overwrite_existing)", meta.Filename)
		}
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return merr
	}

	out.Write("stdout", "Downloading "+meta.Filename+" from registry "+meta.SourceName+"\n")
	response, err := e.deps.RegistryFetch(ctx, meta.SourceName, task.CreatedBy, meta.FilePath())
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: HTTP %d", ErrRegistryAuth, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("registry download failed: HTTP %s", response.Status)
	}
	return e.landStream(ctx, task, out, &landing{
		location: location, role: meta.Role, filename: meta.Filename, target: target,
		body: response.Body, total: response.ContentLength, sourceURL: response.Request.URL.String(),
		checksum: meta.Checksum, algorithm: meta.ChecksumAlgorithm, registry: meta.registryRef(),
	})
}

// registryRef answers the registry file the metadata names, the index's row for the file when it lists one, else the address alone.
func (m *RegistryDownloadMetadata) registryRef() *RegistryRef {
	return &RegistryRef{
		SourceName: m.SourceName, Organization: m.Organization, Download: m.Download,
		Release: m.Release, Patch: m.Patch, Key: m.Filename, Kind: m.Kind, SHA256: strings.ToLower(m.Checksum),
	}
}
