package assets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScanOptions are one scan's knobs (zoneweaver's scan metadata).
type ScanOptions struct {
	// VerifyChecksums re-hashes every present file (otherwise known-present
	// rows refresh existence only — new files always hash: hash verification
	// is the point, Mark's SHI ruling).
	VerifyChecksums bool `json:"verify_checksums"`
	// RemoveOrphaned deletes rows whose file is gone AND that carry no hash
	// expectation (expectation rows always survive as exists:false).
	RemoveOrphaned bool `json:"remove_orphaned"`
}

// ScanResult is one location scan's tally.
type ScanResult struct {
	Scanned    int `json:"scanned"`
	Added      int `json:"added"`
	Removed    int `json:"removed"`
	Mismatched int `json:"mismatched"`
	Missing    int `json:"missing"`
}

// foundFile is one on-disk file a scan discovered.
type foundFile struct {
	role     string
	filename string
	path     string
	size     int64
}

// listLocationFiles walks a location's layout: flat + extension-filtered for
// iso/image, <role>/<file> for the cache types.
func listLocationFiles(location *Location, extensions []string) ([]foundFile, error) {
	found := []foundFile{}
	if RoleKeyed(location.Type) {
		roles, err := os.ReadDir(location.Path)
		if err != nil {
			return nil, err
		}
		for _, roleEntry := range roles {
			if !roleEntry.IsDir() || !ValidRole(roleEntry.Name()) {
				continue
			}
			files, derr := os.ReadDir(filepath.Join(location.Path, roleEntry.Name()))
			if derr != nil {
				continue
			}
			for _, file := range files {
				if file.IsDir() || !ValidFilename(file.Name()) {
					continue
				}
				info, ierr := file.Info()
				if ierr != nil {
					continue
				}
				found = append(found, foundFile{
					role:     roleEntry.Name(),
					filename: file.Name(),
					path:     filepath.Join(location.Path, roleEntry.Name(), file.Name()),
					size:     info.Size(),
				})
			}
		}
		return found, nil
	}

	entries, err := os.ReadDir(location.Path)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !ValidFilename(entry.Name()) {
			continue
		}
		if !matchesExtension(entry.Name(), extensions) {
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		found = append(found, foundFile{
			filename: entry.Name(),
			path:     filepath.Join(location.Path, entry.Name()),
			size:     info.Size(),
		})
	}
	return found, nil
}

func matchesExtension(name string, extensions []string) bool {
	for _, ext := range extensions {
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

// ScanLocation reconciles one location's rows with its directory: new files
// hash and register, known-present rows refresh (re-hash on
// verify_checksums), vanished files mark missing (expectations survive;
// remove_orphaned deletes expectation-less rows). Mismatch counts land in
// the result — the caller decides whether they fail the operation.
func (s *Store) ScanLocation(ctx context.Context, location *Location,
	extensions []string, opts *ScanOptions, report func(stream, line string),
) (*ScanResult, error) {
	if report == nil {
		report = func(string, string) {}
	}
	result := &ScanResult{}

	found, err := listLocationFiles(location, extensions)
	if err != nil {
		_ = s.SetLocationScanResult(ctx, location.ID, err)
		return nil, fmt.Errorf("scan %s: %w", location.Name, err)
	}

	known, err := s.ListByLocation(ctx, location.ID)
	if err != nil {
		return nil, err
	}
	knownByPath := make(map[string]*Artifact, len(known))
	for _, artifact := range known {
		if artifact.Path != "" {
			knownByPath[artifact.Path] = artifact
		}
	}

	foundPaths := map[string]bool{}
	for _, file := range found {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		foundPaths[file.path] = true
		existing := knownByPath[file.path]
		if existing != nil && existing.Exists && !opts.VerifyChecksums &&
			existing.Size == file.size {
			result.Scanned++
			continue
		}
		sha, size, herr := HashFile(file.path)
		if herr != nil {
			report("stderr", file.path+": hash failed ("+herr.Error()+")\n")
			continue
		}
		artifact, rerr := s.RecordIngested(ctx, &Ingested{
			LocationID: location.ID, Role: file.role, Kind: location.Type,
			Filename: file.filename, Path: file.path, SHA256: sha, Size: size,
		})
		if rerr != nil {
			report("stderr", file.path+": registry update failed ("+rerr.Error()+")\n")
			continue
		}
		result.Scanned++
		switch {
		case existing == nil:
			result.Added++
			report("stdout", "Registered "+artifact.Filename+" ("+sha+")\n")
		case artifact.Verified():
		default:
			result.Mismatched++
			report("stderr", "HASH MISMATCH "+artifact.Filename+": file "+
				artifact.SHA256+" != expected "+artifact.ExpectedSHA256+"\n")
		}
	}

	for _, artifact := range known {
		if artifact.Path == "" || foundPaths[artifact.Path] {
			continue
		}
		if !artifact.Exists && !opts.RemoveOrphaned {
			continue
		}
		if opts.RemoveOrphaned && artifact.ExpectedSHA256 == "" {
			if derr := s.DeleteRow(ctx, artifact.ID); derr != nil {
				report("stderr", artifact.Filename+": orphan removal failed ("+derr.Error()+")\n")
				continue
			}
			result.Removed++
			report("stdout", "Removed orphaned record "+artifact.Filename+"\n")
			continue
		}
		if artifact.Exists {
			if merr := s.MarkMissing(ctx, artifact.ID); merr != nil {
				report("stderr", artifact.Filename+": mark missing failed ("+merr.Error()+")\n")
				continue
			}
			result.Missing++
			report("stderr", artifact.Filename+" is gone — marked missing (expectation kept)\n")
		}
	}

	if serr := s.RefreshLocationStats(ctx, location.ID); serr != nil {
		return nil, serr
	}
	if serr := s.SetLocationScanResult(ctx, location.ID, nil); serr != nil {
		return nil, serr
	}
	return result, nil
}
