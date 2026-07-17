package provisioner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// OpImport is the provisioner-import task operation (category system: one
// import writes into the shared registry at a time).
const OpImport = "provisioner_import"

// Import source kinds (SHI's three import paths, design §5).
const (
	SourceFolder  = "folder"
	SourceArchive = "archive"
	SourceGit     = "git"
)

// rootSearchDepth is how deep the package-root search descends — SHI's
// 3-level search, covering archives and clones that nest the package.
const rootSearchDepth = 3

// branchPattern accepts git branch names while rejecting option injection
// (no leading dash) and shell-hostile input.
var branchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)

// tokenNamePattern is the secrets store's entry-name rule.
var tokenNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// checksumPattern is a sha256 hex digest — the archive checksum's only
// legal shape (the converged wire, sync 2026-07-17).
var checksumPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// ImportMetadata is the provisioner_import task's metadata document — the
// import request, verbatim. TokenName names a git_api_keys entry in the
// global secrets store (private-repo imports); the token itself never lands
// in task metadata. CleanupSource removes the archive FILE (never its
// directory) after the attempt — set by the import-upload handler on its own
// temp archives, harmless on a user path but never directory-destructive.
type ImportMetadata struct {
	SourceType    string `json:"source_type"`
	Path          string `json:"path,omitempty"`
	URL           string `json:"url,omitempty"`
	Branch        string `json:"branch,omitempty"`
	TokenName     string `json:"token_name,omitempty"`
	CleanupSource bool   `json:"cleanup_source,omitempty"`
	// Checksum is an optional sha256 hex digest OF THE ARCHIVE (archive
	// imports only — the converged wire, sync 2026-07-17; Mark: "add it"):
	// verified against the archive file before extraction, compared
	// case-insensitively, mismatch = honest task failure.
	Checksum string `json:"checksum,omitempty"`
}

// Validate checks an import request before it becomes a task.
func (m *ImportMetadata) Validate() error {
	switch m.SourceType {
	case SourceFolder, SourceArchive:
		if m.Path == "" {
			return errors.New("path is required for " + m.SourceType + " imports")
		}
		if m.SourceType == SourceArchive && m.Checksum != "" && !checksumPattern.MatchString(m.Checksum) {
			return errors.New("checksum must be a 64-character sha256 hex digest")
		}
	case SourceGit:
		parsed, err := url.Parse(m.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return errors.New("url must be an http(s) git repository URL")
		}
		if m.Branch != "" && !branchPattern.MatchString(m.Branch) {
			return errors.New("branch contains unsupported characters")
		}
		if m.TokenName != "" && !tokenNamePattern.MatchString(m.TokenName) {
			return errors.New("token_name contains unsupported characters")
		}
	default:
		return errors.New(`source_type must be "folder", "archive", or "git"`)
	}
	return nil
}

// RegisterExecutors wires the provisioner operations into the task queue.
// gitToken resolves a git_api_keys secret by name ("" when absent) — a
// function, not the store, so this package stays uncoupled from the secrets
// package. catalogSources are the configured catalogs the install executor
// resolves against.
func RegisterExecutors(queue *tasks.Queue, registry *Registry, gitToken func(name string) string, catalogSources []CatalogSource) {
	e := &executors{queue: queue, registry: registry, gitToken: gitToken, catalogSources: catalogSources}
	queue.Register(OpImport, tasks.Executor{Run: e.importPackage})
	queue.Register(OpExport, tasks.Executor{Run: e.exportVersion})
	queue.Register(OpCatalogInstall, tasks.Executor{Run: e.catalogInstall})
}

type executors struct {
	// queue reaches the task store for live progress (the catalog install's
	// transfer progress — converged, sync 2026-07-17).
	queue          *tasks.Queue
	registry       *Registry
	gitToken       func(name string) string
	catalogSources []CatalogSource
}

// importPackage executes one provisioner_import task: parse the request and
// hand it to the shared import path.
func (e *executors) importPackage(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta ImportMetadata
	if task.Metadata == nil {
		return errors.New("import task has no metadata")
	}
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse import metadata: %w", err)
	}
	return e.runImport(ctx, &meta, out)
}

// runImport is the import path itself — shared by the import task and the
// catalog installer: resolve the source to a directory (extracting or
// cloning first), find the package root, and copy versions into the registry
// — never touching versions already present (update = re-import newer
// version beside old, SHI semantics).
func (e *executors) runImport(ctx context.Context, meta *ImportMetadata, out *tasks.OutputWriter) error {
	if err := meta.Validate(); err != nil {
		return err
	}
	if meta.CleanupSource && meta.SourceType == SourceArchive {
		if clean, cerr := safepath.CleanAbs(meta.Path); cerr == nil {
			defer func() {
				_ = os.Remove(clean)
			}()
		}
	}

	source, cleanup, err := e.resolveSource(ctx, meta, out)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	root, kind := findPackageRoot(source)
	switch kind {
	case collectionManifest:
		out.Write("stdout", "Found provisioner collection at "+root+"\n")
		name, ierr := e.importCollection(root, out)
		if ierr != nil {
			return ierr
		}
		return e.recordSource(meta, name, out)
	case versionManifest:
		out.Write("stdout", "Found provisioner version at "+root+"\n")
		name, ierr := e.importVersion(root, out)
		if ierr != nil {
			return ierr
		}
		return e.recordSource(meta, name, out)
	default:
		return errors.New("no " + collectionManifest + " or " + versionManifest +
			" found within " + strconv.Itoa(rootSearchDepth) + " directory levels of the source")
	}
}

// resolveSource turns the import request into a local directory to search:
// folders are used in place, archives extract into a temp dir, git URLs are
// cloned shallow + recursive (nested submodules — the web_terminal gotcha).
func (e *executors) resolveSource(ctx context.Context, meta *ImportMetadata, out *tasks.OutputWriter) (dir string, cleanup func(), err error) {
	switch meta.SourceType {
	case SourceFolder:
		clean, cerr := safepath.CleanAbs(meta.Path)
		if cerr != nil {
			return "", nil, cerr
		}
		info, serr := os.Stat(clean)
		if serr != nil || !info.IsDir() {
			return "", nil, errors.New("source folder does not exist: " + clean)
		}
		return clean, nil, nil

	case SourceArchive:
		clean, cerr := safepath.CleanAbs(meta.Path)
		if cerr != nil {
			return "", nil, cerr
		}
		if !isArchive(clean) {
			return "", nil, errors.New("archive must be a .tar.gz, .tgz, or .zip file")
		}
		// Archive checksum gate (the converged wire, sync 2026-07-17; Mark:
		// "add it"): verify the sha256 OF THE ARCHIVE before extraction —
		// a mismatch is an honest failure naming expected vs actual.
		if meta.Checksum != "" {
			actual, herr := fileSHA256(clean)
			if herr != nil {
				return "", nil, fmt.Errorf("hash archive for checksum verification: %w", herr)
			}
			if !strings.EqualFold(actual, meta.Checksum) {
				return "", nil, errors.New("archive checksum mismatch: expected " +
					strings.ToLower(meta.Checksum) + ", got " + actual)
			}
			out.Write("stdout", "Archive checksum verified\n")
		}
		temp, terr := os.MkdirTemp("", "hyperweaver-import-*")
		if terr != nil {
			return "", nil, terr
		}
		out.Write("stdout", "Extracting "+filepath.Base(clean)+"\n")
		stats, xerr := extractArchive(clean, temp)
		if xerr != nil {
			_ = removeAllForce(temp)
			return "", nil, xerr
		}
		out.Write("stdout", "Extracted "+strconv.Itoa(stats.Files)+" file(s)\n")
		return temp, func() { _ = removeAllForce(temp) }, nil

	default: // SourceGit — Validate already constrained the vocabulary.
		return e.cloneSource(ctx, meta, out)
	}
}

// cloneSource shallow-clones the repository into a temp dir (SHI's exact
// flags: depth 1, recursive for nested submodules, core.longpaths for
// Windows-hostile trees).
func (e *executors) cloneSource(ctx context.Context, meta *ImportMetadata, out *tasks.OutputWriter) (dir string, cleanup func(), err error) {
	gitExe := gitPath(ctx)
	if gitExe == "" {
		return "", nil, errors.New("git is not installed")
	}
	temp, err := os.MkdirTemp("", "hyperweaver-clone-*")
	if err != nil {
		return "", nil, err
	}

	// Private repositories: the named git_api_keys secret rides as URL
	// userinfo, exactly SHI's clone shape (https://<token>@host/...). Local
	// machine, plain by design (D-C); the narrated URL stays token-free.
	cloneURL := meta.URL
	if meta.TokenName != "" {
		token := ""
		if e.gitToken != nil {
			token = e.gitToken(meta.TokenName)
		}
		if token == "" {
			_ = removeAllForce(temp)
			return "", nil, errors.New("no git API key named " + meta.TokenName + " in the secrets store")
		}
		parsed, perr := url.Parse(meta.URL)
		if perr != nil {
			_ = removeAllForce(temp)
			return "", nil, perr
		}
		parsed.User = url.User(token)
		cloneURL = parsed.String()
	}

	args := []string{"-c", "core.longpaths=true", "clone", "--depth", "1", "--recursive"}
	if meta.Branch != "" {
		args = append(args, "--branch", meta.Branch)
	}
	args = append(args, cloneURL, temp)

	out.Write("stdout", "Cloning "+meta.URL+"\n")
	if cerr := streamCommand(ctx, gitExe, args, out); cerr != nil {
		_ = removeAllForce(temp)
		return "", nil, fmt.Errorf("git clone: %w", cerr)
	}
	return temp, func() { _ = removeAllForce(temp) }, nil
}

// importCollection copies a family into the registry: the collection
// manifest when absent, then every valid version directory not already
// present. Existing versions are narrated and skipped — re-importing is
// idempotent, never destructive. Returns the family name (the provenance
// stamp's key).
func (e *executors) importCollection(root string, out *tasks.OutputWriter) (string, error) {
	manifest, err := readManifest(filepath.Join(root, collectionManifest))
	if err != nil {
		return "", err
	}
	name := metaString(manifest, "name")
	if !ValidName(name) {
		return "", fmt.Errorf("collection manifest carries an unusable name %q", name)
	}

	targetDir, err := safepath.Under(e.registry.Dir(), name)
	if err != nil {
		return "", err
	}
	if merr := os.MkdirAll(targetDir, 0o750); merr != nil {
		return "", merr
	}
	if cerr := copyFileIfAbsent(filepath.Join(root, collectionManifest),
		filepath.Join(targetDir, collectionManifest)); cerr != nil {
		return "", cerr
	}

	imported, skipped := 0, 0
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !ValidName(entry.Name()) {
			continue
		}
		versionRoot := filepath.Join(root, entry.Name())
		if _, verr := readManifest(filepath.Join(versionRoot, versionManifest)); verr != nil {
			continue
		}
		target := filepath.Join(targetDir, entry.Name())
		if _, serr := os.Stat(target); serr == nil {
			out.Write("stdout", name+"/"+entry.Name()+" already present — left untouched\n")
			skipped++
			continue
		}
		// Field-DSL lint gate (fail-closed, design §3.1): an invalid form
		// definition never enters the registry — the refusal lists every
		// problem with the author's own values echoed.
		if problems := LintVersionManifest(versionRoot); len(problems) > 0 {
			return "", lintRefusal(name+"/"+entry.Name(), problems, out)
		}
		out.Write("stdout", "Importing "+name+"/"+entry.Name()+"\n")
		if cerr := copyTree(versionRoot, target); cerr != nil {
			return "", cerr
		}
		narrateRoleSpecs(target, out)
		narrateFieldSchema(target, out)
		imported++
	}

	if imported == 0 && skipped == 0 {
		return "", errors.New("collection " + name + " holds no importable versions")
	}
	out.Write("stdout", "Import complete: "+strconv.Itoa(imported)+" version(s) imported, "+
		strconv.Itoa(skipped)+" already present\n")
	return name, nil
}

// importVersion copies a bare version directory into the registry,
// synthesizing a minimal collection manifest when the family is new (SHI's
// importProvisionerVersion). Returns the family name (the provenance stamp's
// key).
func (e *executors) importVersion(root string, out *tasks.OutputWriter) (string, error) {
	manifest, err := readManifest(filepath.Join(root, versionManifest))
	if err != nil {
		return "", err
	}
	name := metaString(manifest, "name")
	version := metaString(manifest, "version")
	if !ValidName(name) {
		return "", fmt.Errorf("provisioner manifest carries an unusable name %q", name)
	}
	if !ValidName(version) {
		return "", fmt.Errorf("provisioner manifest carries an unusable version %q", version)
	}

	familyDir, err := safepath.Under(e.registry.Dir(), name)
	if err != nil {
		return "", err
	}
	target := filepath.Join(familyDir, version)
	if _, serr := os.Stat(target); serr == nil {
		return "", errors.New(name + "/" + version + " already exists — versions in use are never touched; import a newer version instead")
	}
	if merr := os.MkdirAll(familyDir, 0o750); merr != nil {
		return "", merr
	}

	if _, serr := os.Stat(filepath.Join(familyDir, collectionManifest)); errors.Is(serr, fs.ErrNotExist) {
		if werr := synthesizeCollectionManifest(familyDir, name, metaString(manifest, "description")); werr != nil {
			return "", werr
		}
		out.Write("stdout", "Created collection manifest for new family "+name+"\n")
	}

	// Field-DSL lint gate (fail-closed, design §3.1).
	if problems := LintVersionManifest(root); len(problems) > 0 {
		return "", lintRefusal(name+"/"+version, problems, out)
	}
	out.Write("stdout", "Importing "+name+"/"+version+"\n")
	if cerr := copyTree(root, target); cerr != nil {
		return "", cerr
	}
	narrateRoleSpecs(target, out)
	narrateFieldSchema(target, out)
	out.Write("stdout", "Import complete: "+name+"/"+version+"\n")
	return name, nil
}

// recordSource stamps a family's git provenance beside its collection
// manifest (sourceFileName — the converged registry-side sidecar, sync
// 2026-07-17): {source_type, url, branch?, token_name?}. token_name NAMES a
// secrets-store entry (Mark's private-repo ruling 2026-07-17) — the token
// itself never lands here; refresh resolves it at run time. Git imports only
// — folder, archive, and catalog imports return without touching an existing
// sidecar; a git re-import refreshes it.
func (e *executors) recordSource(meta *ImportMetadata, name string, out *tasks.OutputWriter) error {
	if meta.SourceType != SourceGit {
		return nil
	}
	familyDir, err := safepath.Under(e.registry.Dir(), name)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(&Source{
		SourceType: SourceGit,
		URL:        meta.URL,
		Branch:     meta.Branch,
		TokenName:  meta.TokenName,
	})
	if err != nil {
		return err
	}
	if werr := safepath.WriteFile(filepath.Join(familyDir, sourceFileName),
		append(raw, '\n'), 0o644); werr != nil {
		return werr
	}
	out.Write("stdout", "Recorded git source for "+name+"\n")
	return nil
}

// lintRefusal narrates every DSL lint problem and fails the import — the
// fail-closed rule: nothing partial ever lands.
func lintRefusal(label string, problems []string, out *tasks.OutputWriter) error {
	out.Write("stderr", label+": field DSL rejected ("+strconv.Itoa(len(problems))+" problem(s)):\n")
	for _, problem := range problems {
		out.Write("stderr", "  - "+problem+"\n")
	}
	return errors.New(label + " has an invalid field DSL — fix the manifest and re-import (" +
		strconv.Itoa(len(problems)) + " problem(s) listed in the task output)")
}

// narrateFieldSchema derives the imported version's schema.json (design
// §3.1's interop artifact); failures narrate, never fail the import — the
// lint already proved the DSL parses.
func narrateFieldSchema(versionRoot string, out *tasks.OutputWriter) {
	count, err := BuildFieldSchema(versionRoot)
	if err != nil {
		out.Write("stderr", "schema.json derivation failed: "+err.Error()+"\n")
		return
	}
	if count > 0 {
		out.Write("stdout", "Derived schema.json for "+strconv.Itoa(count)+" field(s)\n")
	}
}

// narrateRoleSpecs builds the imported version's role-specs cache (Mark's
// argument-specs ruling — derived at import); failures narrate, never fail
// the import (the read path self-heals).
func narrateRoleSpecs(versionRoot string, out *tasks.OutputWriter) {
	count, err := BuildRoleSpecs(versionRoot)
	if err != nil {
		out.Write("stderr", "role-specs cache build failed (rebuilt on first read): "+err.Error()+"\n")
		return
	}
	if count > 0 {
		out.Write("stdout", "Cached argument specs for "+strconv.Itoa(count)+" role(s)\n")
	}
}

// findPackageRoot searches dir (breadth-first, rootSearchDepth levels) for a
// package root, preferring a collection root over a bare version root at any
// depth. Returns the winning manifest name as the kind ("" when neither
// exists).
func findPackageRoot(dir string) (root, kind string) {
	versionRoot := ""
	level := []string{dir}
	for depth := 0; depth <= rootSearchDepth; depth++ {
		next := []string{}
		for _, candidate := range level {
			if _, err := os.Stat(filepath.Join(candidate, collectionManifest)); err == nil {
				return candidate, collectionManifest
			}
			if versionRoot == "" {
				if _, err := os.Stat(filepath.Join(candidate, versionManifest)); err == nil {
					versionRoot = candidate
				}
			}
			entries, err := os.ReadDir(candidate)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() && entry.Name() != ".git" {
					next = append(next, filepath.Join(candidate, entry.Name()))
				}
			}
		}
		level = next
	}
	if versionRoot != "" {
		return versionRoot, versionManifest
	}
	return "", ""
}

// copyTree copies a package tree, preserving file modes, skipping .git
// DIRECTORIES (repo history stays out of the registry; the one-line gitlink
// FILES inside submodule checkouts are ordinary files and copy through —
// the observed SHI on-disk format keeps them) and skipping irregular
// entries.
func copyTree(src, dst string) error {
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
		if d.IsDir() && d.Name() == ".git" && rel != "." {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)

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
			// Symlinks and other irregulars never enter the registry.
			return nil
		}
	})
}

// copyFile copies one file with the given mode through the shared writer
// (safepath.WriteFile — the agent's ONE file-write path). An existing
// destination is replaced (the working-copy refresh relies on that); use
// copyFileIfAbsent where existing files must survive.
func copyFile(src, dst string, perm fs.FileMode) error {
	if perm == 0 {
		perm = 0o644
	}
	data, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return err
	}
	return safepath.WriteFile(dst, data, perm)
}

// synthesizeCollectionManifest writes a minimal family manifest when none
// exists — bare-version imports (the flattened repos: the root IS the
// version tree) and registry-shaped seed archives both arrive without one.
// An existing manifest is never touched.
func synthesizeCollectionManifest(familyDir, name, description string) error {
	manifestPath := filepath.Join(familyDir, collectionManifest)
	if _, err := os.Stat(manifestPath); err == nil {
		return nil
	}
	synthesized := "name: " + name + "\ndescription: " + strconv.Quote(description) + "\n"
	return safepath.WriteFile(manifestPath, []byte(synthesized), 0o644)
}

// copyFileIfAbsent copies src to dst unless dst already exists.
func copyFileIfAbsent(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	return copyFile(src, dst, info.Mode().Perm())
}

// fileSHA256 hashes one file, streaming — the archive-checksum gate's hash
// (downloadVerified hashes in flight; here the file already sits on disk).
func fileSHA256(path string) (string, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()
	hasher := sha256.New()
	if _, cerr := io.Copy(hasher, file); cerr != nil {
		return "", cerr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// gitPath returns the validated git path from the prerequisite detector, or
// "" when git is not installed.
func gitPath(ctx context.Context) string {
	for _, tool := range prereqs.Detect(ctx) {
		if tool.Name == "git" && tool.Installed {
			return tool.Path
		}
	}
	return ""
}

// streamCommand runs one external command, streaming stdout and stderr line
// by line into the task output (the vagrant package's streaming shape). The
// context is the kill switch (task cancellation, D-F).
func streamCommand(ctx context.Context, exe string, args []string, out *tasks.OutputWriter) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = procattr.NoConsole()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		forwardLines(stdout, "stdout", out)
	}()
	forwardLines(stderr, "stderr", out)
	<-stdoutDone

	return cmd.Wait()
}

// forwardLines feeds a pipe into the task output line by line.
func forwardLines(r io.Reader, stream string, out *tasks.OutputWriter) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		out.Write(stream, scanner.Text()+"\n")
	}
}
