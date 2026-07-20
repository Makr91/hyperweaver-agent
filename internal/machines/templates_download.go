package machines

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// TemplateDownloadMetadata is the template_download task's metadata document
// (handleAutoDownload's shape). Auth tokens NEVER ride task metadata (the
// house secrets rule the HCL downloader set): private-box credentials live
// on the configured source (template_sources.sources[].auth_token) and the
// executor reads them there.
type TemplateDownloadMetadata struct {
	SourceName   string `json:"source_name"`
	Organization string `json:"organization"`
	BoxName      string `json:"box_name"`
	Version      string `json:"version"`
	Provider     string `json:"provider"`
	Architecture string `json:"architecture"`
}

// templateDownload executes one template_download task: stream the .box from
// the registry, checksum it, extract the disk image into the templates root,
// register the row — DownloadExecutor's flow with the ZFS import replaced by
// the disk-image placement this hypervisor clones from.
func (e *executors) templateDownload(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta TemplateDownloadMetadata
	if len(task.Metadata) == 0 {
		return errors.New("template_download task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return fmt.Errorf("parse template_download metadata: %w", err)
	}
	if meta.Version == "" || meta.Version == "latest" {
		return errors.New("template_download needs a specific version — resolve latest at request time")
	}
	if meta.Architecture == "" {
		meta.Architecture = "amd64"
	}
	if meta.Provider == "" {
		meta.Provider = TemplateProvider
	}

	source, err := findTemplateSource(e.env.TemplateSources, meta.SourceName)
	if err != nil {
		return err
	}
	if existing, ferr := e.store.FindTemplate(ctx, meta.Organization, meta.BoxName,
		meta.Version, meta.Provider, meta.Architecture); ferr == nil && existing != nil {
		out.Write("stdout", "Template already exists locally — nothing to download\n")
		return nil
	}

	e.taskProgress(task, 5, "connecting_to_registry")
	downloadURL := source.URL + "/api/organization/" + url.PathEscape(meta.Organization) +
		"/box/" + url.PathEscape(meta.BoxName) +
		"/version/" + url.PathEscape(meta.Version) +
		"/provider/" + url.PathEscape(meta.Provider) +
		"/architecture/" + url.PathEscape(meta.Architecture) + "/file/download"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, http.NoBody)
	if err != nil {
		return err
	}
	// Registry auth: the source's API key as Bearer (ca_file honored by the
	// client).
	client := registryHTTPClient(source)
	setRegistryAuth(request, registryToken(source))

	out.Write("stdout", "Downloading "+downloadURL+"\n")
	e.taskProgress(task, 10, "downloading")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("template download failed: HTTP %s", response.Status)
	}

	targetDir, err := safepath.Under(e.env.TemplatesDir,
		filepath.Join(meta.Organization, meta.BoxName, meta.Version))
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(targetDir, 0o750); merr != nil {
		return merr
	}
	boxPath := filepath.Join(targetDir, meta.BoxName+".box")

	// Real byte progress on the download window (converged, sync 2026-07-17):
	// bytes map into this step's existing 10→60 percents and progress_info
	// carries {status: "downloading", received_bytes, total_bytes|null} —
	// total from Content-Length (-1 = unknown parks the percent at 10).
	progress := tasks.NewTransferProgress(e.queue.Store(), task.ID, "downloading",
		10, 60, response.ContentLength)
	hasher := sha256.New()
	size, err := safepath.WriteFileFrom(boxPath,
		progress.Reader(io.TeeReader(response.Body, hasher), 0), 0o600)
	if err != nil {
		return err
	}
	progress.Finish()
	checksum := hex.EncodeToString(hasher.Sum(nil))
	out.Write("stdout", fmt.Sprintf("Downloaded %d bytes (sha256 %s)\n", size, checksum))

	e.taskProgress(task, 60, "extracting_box")
	diskPath, boxMetadata, err := extractBoxDisk(boxPath, targetDir)
	if err != nil {
		return err
	}
	// The .box archive is spent once the disk image is out.
	if rerr := os.Remove(boxPath); rerr != nil {
		out.Write("stderr", "Temp .box cleanup failed: "+rerr.Error()+"\n")
	}

	e.taskProgress(task, 95, "saving_record")
	if cerr := e.store.createTemplate(ctx, &Template{
		SourceName:   source.Name,
		Organization: meta.Organization,
		BoxName:      meta.BoxName,
		Version:      meta.Version,
		Provider:     meta.Provider,
		Architecture: meta.Architecture,
		DiskPath:     diskPath,
		Size:         size,
		Checksum:     checksum,
		SourceURL:    downloadURL,
		Metadata:     boxMetadata,
	}); cerr != nil {
		return cerr
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Template "+meta.Organization+"/"+meta.BoxName+" v"+meta.Version+
		" imported to "+diskPath+"\n")
	return nil
}

// findTemplateSource resolves a configured source by name (empty name = the
// source flagged default — names are pure display, never behavior; the
// "Default Registry" name-match fallback died with Mark's real-name ask,
// 2026-07-09).
func findTemplateSource(sources []TemplateSource, name string) (*TemplateSource, error) {
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
		return nil, errors.New("template source not found or disabled: " + name)
	}
	return nil, errors.New("no default template source configured")
}

// FindTemplateSourceForURL maps a box_url onto a configured source
// (determineSourceFromBoxUrl verbatim); empty boxURL returns the default.
func FindTemplateSourceForURL(sources []TemplateSource, boxURL string) (*TemplateSource, error) {
	if boxURL == "" {
		return findTemplateSource(sources, "")
	}
	for i := range sources {
		if sources[i].Enabled && strings.HasPrefix(boxURL, sources[i].URL) {
			return &sources[i], nil
		}
	}
	return nil, errors.New("no configured source matches box_url: " + boxURL)
}

// extractBoxDisk pulls the disk image (and metadata.json) out of a .box
// archive (a gzipped tar: disk image + box.ovf + metadata.json +
// Vagrantfile). The image lands beside the archive; the OVF wrapper is not
// needed — create's storage child clones the raw image. UTM boxes carry a
// box.utm BUNDLE (a directory tree) instead of a disk image: its entries
// extract under targetDir with their relative tree preserved and the bundle
// directory becomes diskPath (create's utm config child imports it whole).
func extractBoxDisk(boxPath, targetDir string) (diskPath string, metadata json.RawMessage, err error) {
	file, err := os.Open(filepath.Clean(boxPath))
	if err != nil {
		return "", nil, err
	}
	defer func() {
		_ = file.Close()
	}()
	unzipped, err := gzip.NewReader(file)
	if err != nil {
		return "", nil, fmt.Errorf("open .box archive: %w", err)
	}
	reader := tar.NewReader(unzipped)

	utmBundle := ""
	for {
		header, herr := reader.Next()
		if errors.Is(herr, io.EOF) {
			break
		}
		if herr != nil {
			return "", nil, fmt.Errorf("read .box archive: %w", herr)
		}
		slashName := filepath.ToSlash(header.Name)
		if idx := strings.Index(slashName, "box.utm/"); idx >= 0 {
			// Pure directory headers skip — directories materialize as the
			// files beneath them land.
			if header.Typeflag == tar.TypeDir {
				continue
			}
			target, terr := safepath.Under(targetDir, filepath.FromSlash(slashName[idx:]))
			if terr != nil {
				return "", nil, terr
			}
			if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
				return "", nil, merr
			}
			if _, werr := safepath.WriteFileFrom(target, reader, 0o600); werr != nil {
				return "", nil, werr
			}
			if utmBundle == "" {
				bundle, berr := safepath.Under(targetDir, "box.utm")
				if berr != nil {
					return "", nil, berr
				}
				utmBundle = bundle
			}
			continue
		}
		name := filepath.Base(header.Name)
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".vmdk") || strings.HasSuffix(lower, ".vdi"):
			target, terr := safepath.Under(targetDir, name)
			if terr != nil {
				return "", nil, terr
			}
			if _, werr := safepath.WriteFileFrom(target, reader, 0o600); werr != nil {
				return "", nil, werr
			}
			diskPath = target
		case lower == "metadata.json":
			raw, rerr := io.ReadAll(io.LimitReader(reader, 1<<20))
			if rerr == nil && json.Valid(raw) {
				metadata = raw
			}
		}
	}
	if utmBundle != "" {
		diskPath = utmBundle
	}
	if diskPath == "" {
		return "", nil, errors.New(".box archive carries no VMDK/VDI disk image")
	}
	return diskPath, metadata, nil
}
