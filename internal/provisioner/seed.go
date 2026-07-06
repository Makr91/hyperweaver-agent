package provisioner

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Provisioners are distributed zipped/tarred, never as unextracted trees
// (Mark's ruling, 2026-07-05): release packaging stages each bundled
// provisioner family as one archive in a seed directory, and the agent
// extracts them on startup with Go's stdlib — no 7zip dll, no external
// tools, the same path on every OS. This replaces SHI's Mac/Linux-only
// diff/overwrite logic and closes its Windows seeding gap.

// seedDirs returns the candidate directories installers stage provisioner
// archives into — beside the executable (Windows installer layout), in the
// macOS bundle's Resources, and the Debian package's share directory.
func seedDirs() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	exeDir := filepath.Dir(exe)
	dirs := []string{
		filepath.Join(exeDir, "provisioners-seed"),
		// macOS bundle layout: Contents/MacOS/<exe> → Contents/Resources.
		filepath.Join(exeDir, "..", "Resources", "provisioners-seed"),
	}
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		dirs = append(dirs, "/usr/share/hyperweaver-agent/provisioners-seed")
	}
	return dirs
}

// Seed extracts every installer-shipped provisioner archive into the
// registry. Non-clobbering by construction (extractArchive's rule): existing
// version directories and files are never touched, so seeding is safe on
// every boot and across upgrades — new bundled versions land beside the old,
// user-imported packages survive untouched. No seed directory is not an
// error; dev builds ship none.
func Seed(provisionersDir string) error {
	archives := []string{}
	for _, dir := range seedDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() && isArchive(entry.Name()) {
				archives = append(archives, filepath.Join(dir, entry.Name()))
			}
		}
	}
	if len(archives) == 0 {
		return nil
	}
	sort.Strings(archives)

	for _, archive := range archives {
		stats, err := extractArchive(archive, provisionersDir)
		if err != nil {
			plog().Error("provisioner seeding failed",
				"archive", archive, "files_written", stats.Files, "error", err)
			return err
		}
		if stats.Files > 0 {
			plog().Info("provisioner archive seeded", "archive", filepath.Base(archive),
				"files_written", stats.Files, "entries_skipped", stats.Skipped)
		} else {
			plog().Debug("provisioner archive already seeded",
				"archive", filepath.Base(archive), "entries_skipped", stats.Skipped)
		}
	}

	names := make([]string, 0, len(archives))
	for _, archive := range archives {
		names = append(names, filepath.Base(archive))
	}
	plog().Info("provisioner seeding complete",
		"archives", strings.Join(names, ", "), "registry", provisionersDir)
	return nil
}
