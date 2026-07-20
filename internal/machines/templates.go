package machines

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The template registry — zoneweaver's Template model + DownloadExecutor
// ported: one DB row per downloaded box, the disk image stored under the
// templates root (<storage>/<org>/<box>/<version>/), downloads over the
// Vagrant/BoxVault-compatible API. On this hypervisor the imported artifact
// is the box's disk image (VMDK/VDI) instead of a ZFS stream; create's
// storage child clones it per machine.

// OpTemplateDownload is the template download task operation.
const OpTemplateDownload = "template_download"

// OpTemplateDelete is the local-template delete task operation (the base's
// template_delete: destroy the stored artifact, drop the row).
const OpTemplateDelete = "template_delete"

// OpTemplateMove is the local-template relocation task (the base's
// template_move: zfs rename / send-recv; here a file move — cross-volume
// falls back to copy+delete).
const OpTemplateMove = "template_move"

// TemplateProvider is this agent's provider value in the registry tuple.
const TemplateProvider = "virtualbox"

// TemplateProviderUTM is the registry provider value for UTM boxes (the .box
// carries a box.utm bundle instead of a VMDK/VDI disk image).
const TemplateProviderUTM = "utm"

// TemplateProviderFor maps a spec's hypervisor onto the registry provider
// value (""/virtualbox → virtualbox, utm → utm).
func TemplateProviderFor(hypervisor string) string {
	if hypervisor == HypervisorUTM {
		return TemplateProviderUTM
	}
	return TemplateProvider
}

// ErrTemplateNotFound reports no usable local template for the tuple.
var ErrTemplateNotFound = errors.New("template not available locally")

// TemplateMigrations is appended to the agent.sqlite migration list.
var TemplateMigrations = []string{
	`CREATE TABLE templates (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		source_name   TEXT NOT NULL,
		organization  TEXT NOT NULL,
		box_name      TEXT NOT NULL,
		version       TEXT NOT NULL,
		provider      TEXT NOT NULL,
		architecture  TEXT NOT NULL,
		disk_path     TEXT NOT NULL,
		size          INTEGER NOT NULL DEFAULT 0,
		checksum      TEXT,
		source_url    TEXT,
		metadata      TEXT,
		downloaded_at TEXT NOT NULL,
		UNIQUE (organization, box_name, version, provider, architecture)
	);`,
}

// Template is one registry row.
type Template struct {
	ID           int64           `json:"id"`
	SourceName   string          `json:"source_name"`
	Organization string          `json:"organization"`
	BoxName      string          `json:"box_name"`
	Version      string          `json:"version"`
	Provider     string          `json:"provider"`
	Architecture string          `json:"architecture"`
	DiskPath     string          `json:"disk_path"`
	Size         int64           `json:"size"`
	Checksum     string          `json:"checksum"`
	SourceURL    string          `json:"source_url"`
	Metadata     json.RawMessage `json:"metadata"`
	DownloadedAt time.Time       `json:"downloaded_at"`
}

// TemplateSource is one configured registry (template_sources.sources[]).
type TemplateSource struct {
	Name    string `json:"name"    yaml:"name"`
	URL     string `json:"url"     yaml:"url"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Default bool   `json:"default" yaml:"default"`
	// AuthToken is the registry API key — a BoxVault service-account token,
	// sent raw as Bearer on every call (vagrant's own model; Mark's ruling
	// 2026-07-09: "API keys, PERIOD"). The ONLY credential: the base's
	// username/JWT signin ladder is deliberately dead.
	AuthToken string `json:"auth_token,omitempty" yaml:"auth_token"`
	// CAFile adds a PEM CA bundle to the trust store for THIS registry —
	// the self-signed-registry answer (verification always stays on; the
	// base's verify_ssl:false has no analog here by design).
	CAFile string `json:"ca_file,omitempty" yaml:"ca_file"`
}

const templateColumns = `id, source_name, organization, box_name, version,
	provider, architecture, disk_path, size, checksum, source_url, metadata,
	downloaded_at`

func scanTemplate(row interface{ Scan(...any) error }) (*Template, error) {
	var t Template
	var checksum, sourceURL, metadata sql.NullString
	var downloadedAt string
	err := row.Scan(&t.ID, &t.SourceName, &t.Organization, &t.BoxName, &t.Version,
		&t.Provider, &t.Architecture, &t.DiskPath, &t.Size, &checksum, &sourceURL,
		&metadata, &downloadedAt)
	if err != nil {
		return nil, err
	}
	t.Checksum = checksum.String
	t.SourceURL = sourceURL.String
	if metadata.Valid {
		t.Metadata = json.RawMessage(metadata.String)
	}
	if t.DownloadedAt, err = time.Parse(timeLayout, downloadedAt); err != nil {
		return nil, fmt.Errorf("template %d: parse downloaded_at: %w", t.ID, err)
	}
	return &t, nil
}

// ListTemplates returns every registry row, newest first.
func (s *Store) ListTemplates(ctx context.Context) ([]*Template, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+templateColumns+` FROM templates
		ORDER BY organization ASC, box_name ASC, version DESC`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()
	list := []*Template{}
	for rows.Next() {
		t, serr := scanTemplate(rows)
		if serr != nil {
			return nil, serr
		}
		list = append(list, t)
	}
	return list, rows.Err()
}

// FindTemplate resolves a box tuple to a local template — the base's
// resolveBoxToTemplate: version "latest" (or empty) takes the newest row,
// and the disk image is re-verified to exist on disk: a stale row (image
// deleted by hand) self-deletes and the lookup reports not-found. provider
// picks the hypervisor's registry rows (TemplateProvider | TemplateProviderUTM).
func (s *Store) FindTemplate(ctx context.Context, org, box, version, provider, arch string) (*Template, error) {
	if arch == "" {
		arch = "amd64"
	}
	query := `SELECT ` + templateColumns + ` FROM templates
		WHERE organization = ? AND box_name = ? AND architecture = ? AND provider = ?`
	args := []any{org, box, arch, provider}
	if version != "" && version != "latest" {
		query += ` AND version = ?`
		args = append(args, version)
	}
	query += ` ORDER BY version DESC LIMIT 1`

	template, err := scanTemplate(s.db.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTemplateNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, serr := os.Stat(template.DiskPath); serr != nil {
		mlog().Warn("template disk image missing, removing stale record",
			"box", org+"/"+box, "disk_path", template.DiskPath)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM templates WHERE id = ?`, template.ID)
		return nil, ErrTemplateNotFound
	}
	return template, nil
}

// GetTemplate returns one registry row by id (ErrTemplateNotFound when
// absent).
func (s *Store) GetTemplate(ctx context.Context, id int64) (*Template, error) {
	template, err := scanTemplate(s.db.QueryRowContext(ctx,
		`SELECT `+templateColumns+` FROM templates WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTemplateNotFound
	}
	return template, err
}

// DeleteTemplate removes one registry row.
func (s *Store) DeleteTemplate(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM templates WHERE id = ?`, id)
	return err
}

// templateDeleteMetadata is the template_delete task's metadata (the base's
// {template_id} document).
type templateDeleteMetadata struct {
	TemplateID int64 `json:"template_id"`
}

// templateDelete executes one template_delete task: release the disk image
// from VirtualBox's media registry and delete it (fallback: plain file
// removal when it was never registered), prune the now-empty version
// directory, drop the row — the base's DeleteExecutor with zfs destroy
// replaced by the disk-image removal this hypervisor stores.
func (e *executors) templateDelete(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta templateDeleteMetadata
	if len(task.Metadata) == 0 {
		return errors.New("template_delete task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return fmt.Errorf("parse template_delete metadata: %w", err)
	}

	template, err := e.store.GetTemplate(ctx, meta.TemplateID)
	if err != nil {
		return fmt.Errorf("template %d: %w", meta.TemplateID, err)
	}
	out.Write("stdout", fmt.Sprintf("Deleting template %s/%s v%s (%s)\n",
		template.Organization, template.BoxName, template.Version, template.DiskPath))

	basePath := filepath.Join(filepath.Dir(template.DiskPath), cloneBaseName)
	if _, serr := os.Stat(basePath); serr == nil {
		vboxExe := VBoxManagePath(ctx)
		if vboxExe == "" {
			return errors.New("template has a clone base but VirtualBox is not installed — cannot verify no machine still links from it")
		}
		hdds, herr := vbox.ListHDDs(ctx, vboxExe)
		if herr != nil {
			return fmt.Errorf("media registry listing for the clone-base children gate: %w", herr)
		}
		baseUUID := ""
		want := filepath.Clean(basePath)
		for i := range hdds {
			if strings.EqualFold(filepath.Clean(hdds[i].Path), want) {
				baseUUID = hdds[i].UUID
				break
			}
		}
		holders := []string{}
		for i := range hdds {
			if baseUUID == "" || hdds[i].ParentUUID != baseUUID {
				continue
			}
			if len(hdds[i].InUseBy) == 0 {
				out.Write("stdout", "Removing orphaned differencing child: "+hdds[i].Path+"\n")
				if cerr := vbox.CloseMedium(ctx, vboxExe, hdds[i].UUID, true); cerr != nil {
					out.Write("stderr", "Orphan child removal failed: "+cerr.Error()+"\n")
				}
				continue
			}
			holders = append(holders, hdds[i].InUseBy...)
		}
		if len(holders) > 0 {
			return errors.New("template clone base is still linked by machine(s): " +
				strings.Join(holders, ", ") + " — delete those machines first")
		}
		out.Write("stdout", "Removing clone base "+basePath+"\n")
		if cerr := vbox.CloseMedium(ctx, vboxExe, basePath, true); cerr != nil {
			out.Write("stderr", "Clone base close failed — removing the file directly: "+cerr.Error()+"\n")
			if rerr := os.Remove(basePath); rerr != nil {
				out.Write("stderr", "Clone base removal failed (continuing): "+rerr.Error()+"\n")
			}
		}
		removeMediumSidecar(basePath)
	}

	if _, serr := os.Stat(template.DiskPath); serr == nil {
		vboxExe := VBoxManagePath(ctx)
		removed := false
		if vboxExe != "" {
			if cerr := vbox.CloseMedium(ctx, vboxExe, template.DiskPath, true); cerr == nil {
				removed = true
			}
		}
		if !removed {
			if rerr := os.Remove(template.DiskPath); rerr != nil {
				// The base continues to the DB cleanup when the dataset destroy
				// fails — same rule here, loudly.
				out.Write("stderr", "Disk image removal failed (row removed anyway): "+rerr.Error()+"\n")
			}
		}
		// The version directory held only this image (+ the spent .box) —
		// prune it when empty; failures are cosmetic.
		if rerr := os.Remove(filepath.Dir(template.DiskPath)); rerr != nil {
			out.Write("stdout", "Version directory left in place (not empty)\n")
		}
	} else {
		out.Write("stdout", "Disk image already gone — removing the row\n")
	}

	if derr := e.store.DeleteTemplate(ctx, template.ID); derr != nil {
		return derr
	}
	out.Write("stdout", fmt.Sprintf("Template %s/%s v%s deleted\n",
		template.Organization, template.BoxName, template.Version))
	return nil
}

// SetTemplateDiskPath records a moved template's new disk image location.
func (s *Store) SetTemplateDiskPath(ctx context.Context, id int64, diskPath string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE templates SET disk_path = ? WHERE id = ?`,
		diskPath, id)
	return err
}

// templateMoveMetadata is the template_move task's metadata: target_path is
// the new storage ROOT — the org/box/version layout is recreated beneath it.
type templateMoveMetadata struct {
	TemplateID int64  `json:"template_id"`
	TargetPath string `json:"target_path"`
}

// templateMove executes one template_move task: relocate the disk image to
// <target_path>/<org>/<box>/<version>/ and update the row. Same-volume moves
// are a rename; cross-volume falls back to copy+delete (the base's zfs
// rename vs send-recv split).
func (e *executors) templateMove(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta templateMoveMetadata
	if len(task.Metadata) == 0 {
		return errors.New("template_move task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return fmt.Errorf("parse template_move metadata: %w", err)
	}

	template, err := e.store.GetTemplate(ctx, meta.TemplateID)
	if err != nil {
		return fmt.Errorf("template %d: %w", meta.TemplateID, err)
	}
	root, err := safepath.CleanAbs(meta.TargetPath)
	if err != nil {
		return fmt.Errorf("target_path is not usable: %w", err)
	}
	targetDir, err := safepath.Under(root,
		filepath.Join(template.Organization, template.BoxName, template.Version))
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(targetDir, 0o750); merr != nil {
		return merr
	}
	targetPath := filepath.Join(targetDir, filepath.Base(template.DiskPath))
	if targetPath == template.DiskPath {
		return errors.New("target path is the same as the current path")
	}
	if _, serr := os.Stat(targetPath); serr == nil {
		return errors.New("a file already exists at the target path: " + targetPath)
	}

	e.taskProgress(task, 20, "moving_disk_image")
	out.Write("stdout", "Moving "+template.DiskPath+" → "+targetPath+"\n")
	if rerr := os.Rename(template.DiskPath, targetPath); rerr != nil {
		out.Write("stdout", "Rename failed (cross-volume?) — copying instead\n")
		if cerr := copyFile(template.DiskPath, targetPath); cerr != nil {
			return cerr
		}
		if derr := os.Remove(template.DiskPath); derr != nil {
			out.Write("stderr", "Source removal after copy failed: "+derr.Error()+"\n")
		}
	}
	// Prune the now-empty old version directory (cosmetic).
	if rerr := os.Remove(filepath.Dir(template.DiskPath)); rerr != nil {
		out.Write("stdout", "Old version directory left in place (not empty)\n")
	}

	e.taskProgress(task, 90, "updating_record")
	if uerr := e.store.SetTemplateDiskPath(ctx, template.ID, targetPath); uerr != nil {
		return uerr
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", fmt.Sprintf("Template %s/%s v%s moved to %s\n",
		template.Organization, template.BoxName, template.Version, targetPath))
	return nil
}

// copyFile streams src to dst (the cross-volume move fallback).
func copyFile(src, dst string) error {
	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() {
		_ = source.Close()
	}()
	if _, err := safepath.WriteFileFrom(dst, source, 0o600); err != nil {
		return err
	}
	return nil
}

// createTemplate registers a downloaded template.
func (s *Store) createTemplate(ctx context.Context, t *Template) error {
	var metadata any
	if t.Metadata != nil {
		metadata = string(t.Metadata)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO templates
		(source_name, organization, box_name, version, provider, architecture,
		 disk_path, size, checksum, source_url, metadata, downloaded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.SourceName, t.Organization, t.BoxName, t.Version, t.Provider,
		t.Architecture, t.DiskPath, t.Size, t.Checksum, t.SourceURL, metadata,
		formatTime(time.Now()))
	return err
}
