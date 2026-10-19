package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// OpRegistrySync is the task that resolves the host's expectations against its box registries.
const OpRegistrySync = "artifact_registry_sync"

// RegistryRef is the BoxVault download file an artifact row is, every member a string.
type RegistryRef struct {
	SourceName   string `json:"source_name"`
	Organization string `json:"organization"`
	Download     string `json:"download"`
	Release      string `json:"release"`
	Patch        string `json:"patch"`
	Key          string `json:"key"`
	Kind         string `json:"kind"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Language     string `json:"language"`
	Variant      string `json:"variant"`
	SHA256       string `json:"sha256"`
}

// ExpectedFile is one file a provisioner's manifest role defaults to: the role's installer_dir, the kind and the file name.
type ExpectedFile struct {
	Role     string
	Kind     string
	Filename string
}

// RegistrySyncMetadata is the artifact_registry_sync task's metadata; source_name narrows the read to one registry.
type RegistrySyncMetadata struct {
	SourceName string `json:"source_name,omitempty"`
}

// RegistryIndex is the files every enabled box registry lists, by sha256 and by file name.
type RegistryIndex struct {
	mu     sync.RWMutex
	bySHA  map[string]RegistryRef
	byName map[string][]RegistryRef
}

func newRegistryIndex() *RegistryIndex {
	return &RegistryIndex{bySHA: map[string]RegistryRef{}, byName: map[string][]RegistryRef{}}
}

func (i *RegistryIndex) add(ref *RegistryRef) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if ref.SHA256 != "" {
		i.bySHA[strings.ToLower(ref.SHA256)] = *ref
	}
	if ref.Key != "" {
		name := strings.ToLower(ref.Key)
		i.byName[name] = append(i.byName[name], *ref)
	}
}

// BySHA answers the registry file carrying the sha256.
func (i *RegistryIndex) BySHA(sha string) (RegistryRef, bool) {
	if i == nil || sha == "" {
		return RegistryRef{}, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	ref, ok := i.bySHA[strings.ToLower(sha)]
	return ref, ok
}

// ByName answers the registry files carrying the file name, in listing order.
func (i *RegistryIndex) ByName(name string) []RegistryRef {
	if i == nil || name == "" {
		return nil
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.byName[strings.ToLower(name)]
}

func stringMember(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

func listMember(object map[string]any, key string) []map[string]any {
	raw, _ := object[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, entry := range raw {
		if object, ok := entry.(map[string]any); ok {
			out = append(out, object)
		}
	}
	return out
}

func organizationOf(download map[string]any) string {
	switch organization := download["organization"].(type) {
	case string:
		return organization
	case map[string]any:
		return stringMember(organization, "name")
	}
	return ""
}

// registryFiles reads every file of a registry's /api/downloads/discover answer as a registry reference.
func registryFiles(sourceName string, decoded any) []RegistryRef {
	refs := []RegistryRef{}
	downloads, _ := decoded.([]any)
	for _, raw := range downloads {
		download, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		organization := organizationOf(download)
		for _, release := range listMember(download, "releases") {
			for _, patch := range listMember(release, "patches") {
				for _, file := range listMember(patch, "files") {
					sha := stringMember(file, "sha256")
					if sha == "" && strings.EqualFold(stringMember(file, "checksum_type"), "SHA256") {
						sha = stringMember(file, "checksum")
					}
					refs = append(refs, RegistryRef{
						SourceName:   sourceName,
						Organization: organization,
						Download:     stringMember(download, "name"),
						Release:      stringMember(release, "version_number"),
						Patch:        stringMember(patch, "name"),
						Key:          stringMember(file, "file_name"),
						Kind:         stringMember(file, "kind"),
						Platform:     stringMember(file, "platform"),
						Architecture: stringMember(file, "architecture"),
						Language:     stringMember(file, "language"),
						Variant:      stringMember(file, "variant"),
						SHA256:       strings.ToLower(sha),
					})
				}
			}
		}
	}
	return refs
}

// VersionOfRegistry answers the structured version a registry file's release and patch name: the release split on dots, the patch as the fix pack when it is not the release itself.
func VersionOfRegistry(ref *RegistryRef) *VersionInfo {
	if ref.Release == "" {
		return nil
	}
	info := &VersionInfo{FullVersion: ref.Release}
	parts := strings.Split(ref.Release, ".")
	if len(parts) > 0 {
		info.Major = parts[0]
	}
	if len(parts) > 1 {
		info.Minor = parts[1]
	}
	if len(parts) > 2 {
		info.Patch = parts[2]
	}
	if ref.Patch != "" && !strings.EqualFold(ref.Patch, "release") {
		info.FixPack = ref.Patch
		info.FullVersion = ref.Release + "_" + ref.Patch
	}
	return info
}

// registryKind answers the row kind a registry file carries, hotfix for interim-fix, empty for a kind the host does not store.
func registryKind(ref *RegistryRef) string {
	kind := NormalizeKind(ref.Kind)
	if RoleKeyed(kind) {
		return kind
	}
	return ""
}

// registrySync executes one artifact_registry_sync task: read every enabled registry's downloads as the person who queued it, rebuild the index, resolve every manifest default against it and stamp every hashed row the registries list.
func (e *executors) registrySync(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta RegistrySyncMetadata
	if len(task.Metadata) > 0 {
		if err := json.Unmarshal(task.Metadata, &meta); err != nil {
			return fmt.Errorf("parse registry sync metadata: %w", err)
		}
	}
	if e.deps.RegistryFetch == nil || e.deps.RegistrySources == nil {
		return errors.New("no box registries are configured")
	}
	sources := e.deps.RegistrySources()
	if meta.SourceName != "" {
		sources = []string{meta.SourceName}
	}
	index := newRegistryIndex()
	listed := 0
	for _, sourceID := range sources {
		refs, err := e.fetchRegistryFiles(ctx, sourceID, task.CreatedBy)
		if err != nil {
			out.Write("stderr", "registry "+sourceID+": "+err.Error()+"\n")
			continue
		}
		for i := range refs {
			index.add(&refs[i])
		}
		listed += len(refs)
		out.Write("stdout", fmt.Sprintf("Registry %s lists %d files\n", sourceID, len(refs)))
	}
	if meta.SourceName == "" {
		e.store.SetRegistryIndex(index)
	} else {
		e.store.MergeRegistryIndex(index)
	}
	e.progress(task.ID, 40, map[string]any{"status": "resolving_expectations"})

	resolved, seeded := 0, 0
	if e.deps.ExpectedFiles != nil {
		for _, expected := range e.deps.ExpectedFiles() {
			kind := NormalizeKind(expected.Kind)
			if !RoleKeyed(kind) || !ValidRole(expected.Role) || !ValidFilename(expected.Filename) {
				continue
			}
			refs := e.store.RegistryIndex().ByName(expected.Filename)
			if len(refs) == 0 {
				location, lerr := e.store.DefaultLocation(ctx, kind)
				if lerr != nil {
					continue
				}
				if serr := e.store.SeedExpectation(ctx, location.ID, expected.Role, kind, expected.Filename, "", nil); serr != nil {
					return serr
				}
				seeded++
				continue
			}
			ref := refs[0]
			if registryKind(&ref) != "" {
				kind = registryKind(&ref)
			}
			location, lerr := e.store.DefaultLocation(ctx, kind)
			if lerr != nil {
				continue
			}
			if uerr := e.store.UpsertExpectation(ctx, location.ID, expected.Role, kind, expected.Filename, ref.SHA256, VersionOfRegistry(&ref), &ref); uerr != nil {
				return uerr
			}
			resolved++
		}
	}
	e.progress(task.ID, 70, map[string]any{"status": "stamping_rows"})

	stamped, err := e.store.StampRegistryRows(ctx)
	if err != nil {
		return err
	}
	out.Write("stdout", fmt.Sprintf("Registry sync: %d files listed, %d manifest defaults resolved, %d seeded without a registry, %d rows stamped\n",
		listed, resolved, seeded, stamped))
	return nil
}

// fetchRegistryFiles reads one registry's downloads listing as the person createdBy stands for.
func (e *executors) fetchRegistryFiles(ctx context.Context, sourceID, createdBy string) ([]RegistryRef, error) {
	response, err := e.deps.RegistryFetch(ctx, sourceID, createdBy, "/api/downloads/discover")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: HTTP %d", ErrRegistryAuth, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloads listing failed: HTTP %s", response.Status)
	}
	var decoded any
	if derr := json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(&decoded); derr != nil {
		return nil, derr
	}
	return registryFiles(sourceID, decoded), nil
}
