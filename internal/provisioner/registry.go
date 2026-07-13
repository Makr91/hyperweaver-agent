package provisioner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// ErrNotFound reports that no provisioner family has the requested name.
var ErrNotFound = errors.New("provisioner not found")

// ErrVersionNotFound reports that a family exists but lacks the requested
// version.
var ErrVersionNotFound = errors.New("provisioner version not found")

// Registry is the provisioner package registry: a directory scanned on
// demand (SHI's discovery model — the filesystem is the source of truth, so
// packages dropped in by installers or by hand appear without registration).
type Registry struct {
	dir string
}

// NewRegistry addresses the registry at dir. The directory may not exist yet
// — an empty registry, not an error.
func NewRegistry(dir string) *Registry {
	return &Registry{dir: dir}
}

// Dir returns the registry root.
func (r *Registry) Dir() string {
	return r.dir
}

// List scans the registry: every top-level directory carrying
// provisioner-collection.yml is a family; every subdirectory carrying a
// parseable provisioner.yml is a version, newest first. Families whose
// manifest is unparseable or that hold zero valid versions are reported with
// valid: false (SHI's "(Invalid)" placeholder) rather than hidden.
func (r *Registry) List() ([]*Collection, error) {
	entries, err := os.ReadDir(r.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []*Collection{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read provisioners dir: %w", err)
	}

	collections := []*Collection{}
	for _, entry := range entries {
		if !entry.IsDir() || !ValidName(entry.Name()) {
			continue
		}
		collection, cerr := r.readCollection(entry.Name())
		if cerr != nil {
			plog().Warn("skipping unreadable provisioner", "name", entry.Name(), "error", cerr)
			continue
		}
		if collection != nil {
			collections = append(collections, collection)
		}
	}
	sort.Slice(collections, func(i, j int) bool {
		return collections[i].Name < collections[j].Name
	})
	return collections, nil
}

// Get returns one family, or ErrNotFound.
func (r *Registry) Get(name string) (*Collection, error) {
	if !ValidName(name) {
		return nil, ErrNotFound
	}
	collection, err := r.readCollection(name)
	if err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, ErrNotFound
	}
	return collection, nil
}

// GetVersion returns one version of a family, matched by its version string
// or its directory name, or ErrNotFound/ErrVersionNotFound.
func (r *Registry) GetVersion(name, version string) (*Version, error) {
	collection, err := r.Get(name)
	if err != nil {
		return nil, err
	}
	if !ValidName(version) {
		return nil, ErrVersionNotFound
	}
	for _, v := range collection.Versions {
		if v.Version == version || v.Dir == version {
			v.RoleSpecs = ReadRoleSpecs(v.Root)
			return v, nil
		}
	}
	return nil, ErrVersionNotFound
}

// Delete removes a whole family. The caller has already established nothing
// references it. Directories without the collection manifest are not
// provisioners and are refused.
func (r *Registry) Delete(name string) error {
	if !ValidName(name) {
		return ErrNotFound
	}
	dir, err := safepath.Under(r.dir, name)
	if err != nil {
		return err
	}
	if _, serr := os.Stat(filepath.Join(dir, collectionManifest)); serr != nil {
		return ErrNotFound
	}
	return removeAllForce(dir)
}

// DeleteVersion removes one version directory, leaving its siblings (and the
// family manifest) in place.
func (r *Registry) DeleteVersion(name, version string) error {
	v, err := r.GetVersion(name, version)
	if err != nil {
		return err
	}
	return removeAllForce(v.Root)
}

// readCollection loads one family by directory name (already validated).
// nil means the directory is not a provisioner (no collection manifest).
func (r *Registry) readCollection(name string) (*Collection, error) {
	dir := filepath.Join(r.dir, name)
	manifestPath := filepath.Join(dir, collectionManifest)
	if _, err := os.Stat(manifestPath); errors.Is(err, fs.ErrNotExist) {
		// Not a provisioner — a normal scan outcome, distinct from errors.
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	collection := &Collection{Name: name, Versions: []*Version{}}
	manifest, manifestErr := readManifest(manifestPath)
	if manifestErr == nil {
		collection.Metadata = manifest
		collection.Description = metaString(manifest, "description")
	} else {
		// An unparseable manifest degrades to an invalid placeholder (SHI
		// behavior) so the UI can show — and the user can delete — it; any
		// version subdirectories still scan.
		collection.Description = "invalid " + collectionManifest + ": " + manifestErr.Error()
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !ValidName(entry.Name()) {
			continue
		}
		root := filepath.Join(dir, entry.Name())
		versionDoc, verr := readManifest(filepath.Join(root, versionManifest))
		if verr != nil {
			// Version subfolders without a parseable provisioner.yml are
			// skipped (SHI rule).
			continue
		}
		version := metaString(versionDoc, "version")
		if version == "" {
			version = entry.Name()
		}
		collection.Versions = append(collection.Versions, &Version{
			Version:     version,
			Dir:         entry.Name(),
			Name:        metaString(versionDoc, "name"),
			Description: metaString(versionDoc, "description"),
			Root:        root,
			Metadata:    versionDoc,
		})
	}

	sort.Slice(collection.Versions, func(i, j int) bool {
		return compareVersions(collection.Versions[i].Version, collection.Versions[j].Version) > 0
	})
	collection.Valid = len(collection.Versions) > 0
	return collection, nil
}

// compareVersions orders dotted version strings (0.1.24-style): dot/dash
// segments compare numerically when both are numeric, lexically otherwise;
// more segments outrank a shared prefix. Returns <0, 0, >0.
func compareVersions(a, b string) int {
	separator := func(r rune) bool { return r == '.' || r == '-' }
	as := strings.FieldsFunc(a, separator)
	bs := strings.FieldsFunc(b, separator)
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.Atoi(as[i])
		bn, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
			continue
		}
		if c := strings.Compare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return len(as) - len(bs)
}

// RemoveTree force-deletes a directory tree (read-only git objects
// included) — the machine-delete path uses it for working-directory
// removal; callers have already established the path is theirs to delete.
func RemoveTree(path string) error {
	return removeAllForce(path)
}

// removeAllForce deletes a tree, clearing read-only file bits on a retry —
// git-object files are read-only on Windows and fail a plain RemoveAll.
func removeAllForce(path string) error {
	err := os.RemoveAll(path)
	if err == nil {
		return nil
	}
	// Best-effort sweep through a root-scoped handle (no symlink TOCTOU
	// escape): 0o600 clears the Windows read-only attribute (all os.Chmod
	// toggles there). Files only — directories never carry git's read-only
	// bit. Failures are left for RemoveAll to report. The handle must close
	// before the retry: Windows will not delete a held-open directory.
	root, rerr := os.OpenRoot(path)
	if rerr != nil {
		return err
	}
	_ = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, werr error) error {
		if werr == nil && !d.IsDir() {
			_ = root.Chmod(p, 0o600)
		}
		return nil
	})
	if cerr := root.Close(); cerr != nil {
		return err
	}
	return os.RemoveAll(path)
}
