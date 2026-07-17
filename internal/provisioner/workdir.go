package provisioner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/sslcert"
)

// Working-directory materialization (architecture §8 Phase-C spec): each
// machine gets a working copy of its provisioner version plus the generated
// Hosts.yml — the layout observed on Mark's live SHI install (design doc
// §11): package payload (core/, templates/, provisioners/, outer
// Vagrantfile, provisioner.yml, version.rb), Hosts.yml, id-files/
// {server-ids,user-ids,user-safe-ids}, installers/<role>/... mount trees,
// and ssls/ pre-seeded with the CA and a default-signed pair. Vagrant runs
// in this directory; Hosts.rb and the package are never modified.

// Names materialization must never clobber (Mark's D-C ruling): Hosts.rb
// merges the working copy's secrets.yml/.secrets.yml at vagrant runtime IN
// ADDITION to the SECRETS_* vars — those files belong to the package/user.
// results.yml is the guest's post-provision answer. The .vagrant tree is
// vagrant's own state.
var preservedWorkdirNames = map[string]bool{
	"secrets.yml":  true,
	".secrets.yml": true,
	"results.yml":  true,
	".vagrant":     true,
}

// installer subtrees per role — SHI's observed installers/<role>/ mount
// layout the folders: blocks target.
var installerSubdirs = []string{"archives", "fixpack", "hotfix", "core"}

// ssls subtrees — the ssl role's expected working-copy tree, pre-seeded.
var sslSubdirs = []string{"ca", "crt", "key", "csr", "jks", "kyr", "pfx", "combined"}

// InstallerFile is one cache-verified file to mount into the working copy's
// installers/<role>/<subdir>/ tree (Mark's ruling 2026-07-06: only files
// whose SHA-256 checked out reach a machine).
type InstallerFile struct {
	// SourcePath is the verified cache location.
	SourcePath string
	// Role/Subdir/Filename place the mount (installers/<role>/<subdir>/<file>).
	Role     string
	Subdir   string
	Filename string
	// SHA256 is the verified hash a copied mount must reproduce.
	SHA256 string
}

// MaterializeInput is everything one working-directory materialization
// consumes.
type MaterializeInput struct {
	// MachineDir is the machine's working directory (MachineDirName under
	// the configured machines root).
	MachineDir string
	// Version is the provisioner package version to copy in.
	Version *Version
	// HostsYML is the rendered Hosts.yml (RenderHostsFile output).
	HostsYML []byte
	// Roles receive installers/<role>/ mount skeletons.
	Roles []RoleInput
	// Installers are the cache-verified files to mount (resolved and
	// hash-checked by the caller against the file cache).
	Installers []InstallerFile
	// SafeIDPath optionally names an agent-host Domino safe-ID file to place
	// under id-files per the package's conventions.
	SafeIDPath string
	// CACertPath/CAKeyPath locate the agent's CA pair (the installer-seeded
	// STARTcloud CA, or the generated one) seeding ssls/ca and signing the
	// default-signed pair.
	CACertPath string
	CAKeyPath  string
}

// MachineDirName derives the on-disk directory name from a machine name
// (design D-G: the name is free-form; the directory is its sanitized form).
func MachineDirName(machineName string) string {
	var b strings.Builder
	for _, r := range machineName {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := strings.Trim(b.String(), ".")
	if name == "" {
		name = "machine"
	}
	return name
}

// Materialize builds (or refreshes) one machine's working directory:
// package files are copied fresh on every call — SHI prepares the working
// copy before every start — while the preserved names (secrets files,
// vagrant state, provision results) and the seeded ssls material survive
// untouched.
func Materialize(in *MaterializeInput) error {
	if in.Version == nil {
		return errors.New("no provisioner version to materialize")
	}
	dir, err := safepath.CleanAbs(in.MachineDir)
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(dir, 0o750); merr != nil {
		return fmt.Errorf("create machine dir: %w", merr)
	}

	if cerr := syncPackage(in.Version.Root, dir); cerr != nil {
		return fmt.Errorf("copy provisioner %s/%s: %w", in.Version.Name, in.Version.Version, cerr)
	}
	if werr := safepath.WriteFile(filepath.Join(dir, "Hosts.yml"), in.HostsYML, 0o600); werr != nil {
		return fmt.Errorf("write Hosts.yml: %w", werr)
	}
	if ierr := materializeIDFiles(dir, in); ierr != nil {
		return ierr
	}
	if ierr := materializeInstallers(dir, in.Roles); ierr != nil {
		return ierr
	}
	if ierr := mountInstallerFiles(dir, in.Installers); ierr != nil {
		return ierr
	}
	return materializeSSLs(dir, in.CACertPath, in.CAKeyPath)
}

// mountInstallerFiles places the cache-verified files into
// installers/<role>/<subdir>/. Same-volume mounts hard-link (SHI's
// hard-link/copy behavior — instant, no duplicate space); cross-volume falls
// back to a hash-verified streaming copy. An existing hard link to the same
// cache file is left in place.
func mountInstallerFiles(dir string, files []InstallerFile) error {
	for i := range files {
		file := &files[i]
		target, err := safepath.Under(dir,
			filepath.Join("installers", file.Role, file.Subdir, file.Filename))
		if err != nil {
			return err
		}
		if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
			return merr
		}

		sourceInfo, err := os.Stat(file.SourcePath)
		if err != nil {
			return fmt.Errorf("cached file %s: %w", file.SourcePath, err)
		}
		if targetInfo, serr := os.Stat(target); serr == nil {
			if os.SameFile(sourceInfo, targetInfo) {
				continue // already hard-linked to the verified cache file
			}
			if rerr := os.Remove(target); rerr != nil {
				return rerr
			}
		}

		if lerr := os.Link(file.SourcePath, target); lerr == nil {
			continue
		}
		// Cross-volume (or a filesystem without hard links): stream a copy
		// and verify the copy reproduces the verified hash.
		src, oerr := os.Open(filepath.Clean(file.SourcePath))
		if oerr != nil {
			return oerr
		}
		hasher := sha256.New()
		_, werr := safepath.WriteFileFrom(target, io.TeeReader(src, hasher), 0o600)
		if cerr := src.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return fmt.Errorf("mount %s: %w", file.Filename, werr)
		}
		if got := hex.EncodeToString(hasher.Sum(nil)); !strings.EqualFold(got, file.SHA256) {
			_ = os.Remove(target)
			return fmt.Errorf("mount %s: copy hashed %s, expected %s — discarded",
				file.Filename, got, file.SHA256)
		}
	}
	return nil
}

// syncPackage copies the package version tree into the working directory,
// overwriting stale package files but never the preserved names and never
// descending into .git directories.
func syncPackage(src, dst string) error {
	cleanSrc, err := safepath.CleanAbs(src)
	if err != nil {
		return err
	}
	return filepath.WalkDir(cleanSrc, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(cleanSrc, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		if preservedWorkdirNames[filepath.ToSlash(rel)] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			// Packages may ship a starter secrets.yml — seed it once; the
			// user's copy is never overwritten afterwards (D-C).
			return copyFileIfAbsent(path, target)
		}

		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		switch {
		case d.IsDir():
			perm := info.Mode().Perm()
			if perm == 0 {
				perm = 0o750
			}
			return os.MkdirAll(target, perm)
		case info.Mode().IsRegular():
			return copyFile(path, target, info.Mode().Perm())
		default:
			return nil
		}
	})
}

// materializeIDFiles creates the id-files tree and places the safe ID per
// the package's conventions — metadata-driven, never code-typed (design
// D-G/§5): provisioner.yml may carry id_files.safe_id_dir (default
// user-safe-ids; the additional-server packages declare server-ids) and
// id_files.keep_original_name (default false — the file lands as safe.ids).
func materializeIDFiles(dir string, in *MaterializeInput) error {
	idRoot := filepath.Join(dir, "id-files")
	for _, sub := range []string{"server-ids", "user-ids", "user-safe-ids"} {
		if err := os.MkdirAll(filepath.Join(idRoot, sub), 0o750); err != nil {
			return err
		}
	}
	if in.SafeIDPath == "" {
		return nil
	}

	safeIDDir := "user-safe-ids"
	keepName := false
	if idFiles, ok := in.Version.Metadata["id_files"].(map[string]any); ok {
		if v, sok := idFiles["safe_id_dir"].(string); sok && v != "" {
			safeIDDir = v
		}
		if v, bok := idFiles["keep_original_name"].(bool); bok {
			keepName = v
		}
	}
	if !ValidName(safeIDDir) {
		return fmt.Errorf("package declares an unusable id_files.safe_id_dir %q", safeIDDir)
	}

	source, err := safepath.CleanAbs(in.SafeIDPath)
	if err != nil {
		return err
	}
	name := "safe.ids"
	if keepName {
		name = filepath.Base(source)
	}
	target, err := safepath.Under(idRoot, filepath.Join(safeIDDir, name))
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return merr
	}
	data, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		return fmt.Errorf("read safe ID %s: %w", source, err)
	}
	return safepath.WriteFile(target, data, 0o600)
}

// materializeInstallers creates the installers/<role>/ mount skeletons for
// every role in the request. The file cache populates them when the assets
// subsystem lands (arch item 3); until then the folders: mounts resolve to
// empty trees.
func materializeInstallers(dir string, roles []RoleInput) error {
	root := filepath.Join(dir, "installers")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return err
	}
	for i := range roles {
		name := roles[i].Name
		if !ValidName(name) {
			return fmt.Errorf("role name %q is unusable as a directory", name)
		}
		for _, sub := range installerSubdirs {
			target, err := safepath.Under(root, filepath.Join(name, sub))
			if err != nil {
				return err
			}
			if merr := os.MkdirAll(target, 0o750); merr != nil {
				return merr
			}
		}
	}
	return nil
}

// materializeSSLs creates the ssls tree and pre-seeds it — SHI's observed
// working copies ship the CA pair (ca-certificate.crt/.key) plus a
// default-signed pair for the ssl role's default-signed path. Existing
// files are never touched; the default-signed pair is generated once,
// signed by the agent's CA (sslcert.EnsureCertificates semantics).
func materializeSSLs(dir, caCertPath, caKeyPath string) error {
	root := filepath.Join(dir, "ssls")
	for _, sub := range sslSubdirs {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o750); err != nil {
			return err
		}
	}
	if caCertPath == "" || caKeyPath == "" {
		return nil
	}

	if err := copyFileIfAbsent(caCertPath, filepath.Join(root, "ca", "ca-certificate.crt")); err != nil {
		return fmt.Errorf("seed working-copy CA certificate: %w", err)
	}
	if err := copyFileIfAbsent(caKeyPath, filepath.Join(root, "ca", "ca-certificate.key")); err != nil {
		return fmt.Errorf("seed working-copy CA key: %w", err)
	}
	// Shape-A hierarchy (Mark's ruling, sync 2026-07-17): the OFFLINE root's
	// certificate — landed beside the CA pair by sslcert.SeedCA — seeds
	// ssls/ca/root-ca.crt so guests hold the whole trust chain. A generated
	// (rootless) CA seeds nothing extra.
	rootSource := filepath.Join(filepath.Dir(caCertPath), "root-ca.crt")
	if _, serr := os.Stat(rootSource); serr == nil {
		if err := copyFileIfAbsent(rootSource, filepath.Join(root, "ca", "root-ca.crt")); err != nil {
			return fmt.Errorf("seed working-copy root CA certificate: %w", err)
		}
	}

	if _, err := sslcert.EnsureCertificates(
		filepath.Join(root, "key", "default-signed.key"),
		filepath.Join(root, "crt", "default-signed.crt"),
		caCertPath, caKeyPath); err != nil {
		return fmt.Errorf("generate default-signed pair: %w", err)
	}
	return nil
}
