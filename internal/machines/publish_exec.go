package machines

import (
	"bytes"
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
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Template publish — the base's template_upload ported: export the machine
// (or take an existing .box), ensure the registry structure (box → version →
// provider → architecture), chunk-upload the artifact with retries, release
// the box. Provider here is "virtualbox". Registry credentials live on the
// configured source ONLY (the house secrets rule — the base's per-request
// auth_token deliberately has no analog: tokens never ride task metadata).

// OpTemplatePublish is the publish task operation (the base's op name).
const OpTemplatePublish = "template_upload"

// publishChunkSize is one upload chunk (the base's upload.chunk_size_mb
// default 100).
const publishChunkSize = 100 * 1024 * 1024

// templatePublishMetadata is the publish task's metadata document.
type templatePublishMetadata struct {
	// MachineName exports that machine first; BoxPath publishes an existing
	// .box file instead. Exactly one is required.
	MachineName  string `json:"machine_name,omitempty"`
	BoxPath      string `json:"box_path,omitempty"`
	SourceName   string `json:"source_name"`
	Organization string `json:"organization"`
	BoxName      string `json:"box_name"`
	Version      string `json:"version"`
	Description  string `json:"description,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

// templatePublish executes one template_upload task.
func (e *executors) templatePublish(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta templatePublishMetadata
	if task.Metadata == nil {
		return errors.New("template_upload task has no metadata")
	}
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse template_upload metadata: %w", err)
	}
	if meta.Architecture == "" {
		meta.Architecture = "amd64"
	}

	source, err := findTemplateSource(e.env.TemplateSources, meta.SourceName)
	if err != nil {
		return err
	}
	client := registryHTTPClient(source)
	token := registryToken(ctx, client, source)

	// The artifact: an existing .box, or a fresh export of the machine.
	boxPath := meta.BoxPath
	var checksum string
	switch {
	case boxPath != "":
		if _, serr := os.Stat(boxPath); serr != nil {
			return fmt.Errorf("box file not found: %s", boxPath)
		}
		e.taskProgress(task, 10, "calculating_checksum")
		if checksum, err = fileSHA256(boxPath); err != nil {
			return err
		}
	case meta.MachineName != "":
		machine, gerr := e.store.Get(ctx, meta.MachineName)
		if gerr != nil {
			return fmt.Errorf("machine %s: %w", meta.MachineName, gerr)
		}
		vboxExe := VBoxManagePath(ctx)
		if vboxExe == "" {
			return errors.New("VirtualBox is not installed")
		}
		filename := fmt.Sprintf("publish-%s-%d.box",
			provisioner.MachineDirName(machine.Name), time.Now().Unix())
		if boxPath, checksum, err = e.buildMachineBox(ctx, task, machine, vboxExe, filename, out); err != nil {
			return err
		}
		// The export is publish's intermediate — spent after the upload.
		defer func() {
			_ = os.Remove(boxPath)
		}()
	default:
		return errors.New("either machine_name or box_path must be provided")
	}

	e.taskProgress(task, 80, "creating_registry_structure")
	base := source.URL + "/api/organization/" + url.PathEscape(meta.Organization) + "/box"
	structure := []struct {
		url      string
		document map[string]any
	}{
		{base, map[string]any{
			"name":        meta.BoxName,
			"description": publishDescription(&meta),
			"isPublic":    false,
		}},
		{base + "/" + url.PathEscape(meta.BoxName) + "/version", map[string]any{
			"versionNumber": meta.Version,
			"description":   publishDescription(&meta),
		}},
		{base + "/" + url.PathEscape(meta.BoxName) + "/version/" + url.PathEscape(meta.Version) +
			"/provider", map[string]any{"name": TemplateProvider}},
		{base + "/" + url.PathEscape(meta.BoxName) + "/version/" + url.PathEscape(meta.Version) +
			"/provider/" + TemplateProvider + "/architecture", map[string]any{
			"name":         meta.Architecture,
			"checksum":     checksum,
			"checksumType": "SHA256",
		}},
	}
	for _, step := range structure {
		status, serr := registryPost(ctx, client, token, step.url, step.document)
		if serr != nil {
			return fmt.Errorf("registry structure: %w", serr)
		}
		if !conflictOK(status) {
			return fmt.Errorf("registry structure: HTTP %d at %s", status, step.url)
		}
	}

	e.taskProgress(task, 85, "uploading_to_registry")
	uploadURL := base + "/" + url.PathEscape(meta.BoxName) +
		"/version/" + url.PathEscape(meta.Version) +
		"/provider/" + TemplateProvider +
		"/architecture/" + url.PathEscape(meta.Architecture) + "/file/upload"
	if uerr := e.uploadChunks(ctx, task, client, token, uploadURL, boxPath, checksum, out); uerr != nil {
		return uerr
	}

	e.taskProgress(task, 95, "releasing_version")
	status, err := registrySend(ctx, client, token, http.MethodPut,
		base+"/"+url.PathEscape(meta.BoxName),
		map[string]any{"name": meta.BoxName, "published": true})
	if err != nil {
		return fmt.Errorf("release: %w", err)
	}
	if !conflictOK(status) {
		return fmt.Errorf("release: HTTP %d", status)
	}

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", fmt.Sprintf("Published %s to %s/%s v%s\n",
		filepath.Base(boxPath), meta.Organization, meta.BoxName, meta.Version))
	return nil
}

func publishDescription(meta *templatePublishMetadata) string {
	if meta.Description != "" {
		return meta.Description
	}
	if meta.MachineName != "" {
		return "Exported from " + meta.MachineName
	}
	return "Exported from file"
}

// uploadChunks streams the .box sequentially in publishChunkSize pieces (the
// base's chunked upload: x-file-name/x-checksum headers, X-Chunk-Index/
// X-Total-Chunks, three retries with exponential backoff, 400/409 = already
// there = success).
func (e *executors) uploadChunks(ctx context.Context, task *tasks.Task, client *http.Client,
	token, uploadURL, boxPath, checksum string, out *tasks.OutputWriter,
) error {
	file, err := os.Open(filepath.Clean(boxPath))
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := info.Size()
	totalChunks := int((fileSize + publishChunkSize - 1) / publishChunkSize)
	if totalChunks == 0 {
		totalChunks = 1
	}
	out.Write("stdout", fmt.Sprintf("Uploading %d MB in %d chunk(s)\n",
		fileSize/(1024*1024), totalChunks))

	buffer := make([]byte, publishChunkSize)
	for index := 0; index < totalChunks; index++ {
		length, rerr := io.ReadFull(file, buffer)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			return rerr
		}
		if uerr := e.uploadChunkWithRetry(ctx, client, token, uploadURL, checksum,
			buffer[:length], index, totalChunks, out); uerr != nil {
			return uerr
		}
		progress := 85 + float64(index+1)/float64(totalChunks)*10
		e.taskProgress(task, progress, fmt.Sprintf("uploading %d/%d", index+1, totalChunks))
	}
	return nil
}

// uploadChunkWithRetry sends one chunk, retrying three times (1s/2s/4s).
func (e *executors) uploadChunkWithRetry(ctx context.Context, client *http.Client,
	token, uploadURL, checksum string, chunk []byte, index, total int, out *tasks.OutputWriter,
) error {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			out.Write("stderr", fmt.Sprintf("Chunk %d failed (%v) — retrying in %s\n",
				index, lastErr, backoff))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
		lastErr = e.uploadChunk(ctx, client, token, uploadURL, checksum, chunk, index, total)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("chunk %d upload failed after 3 retries: %w", index, lastErr)
}

// uploadChunk sends one chunk request.
func (e *executors) uploadChunk(ctx context.Context, client *http.Client,
	token, uploadURL, checksum string, chunk []byte, index, total int,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, registryUploadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, uploadURL,
		bytes.NewReader(chunk))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("x-file-name", "vagrant.box")
	request.Header.Set("x-checksum", checksum)
	request.Header.Set("x-checksum-type", "SHA256")
	request.Header.Set("X-Chunk-Index", fmt.Sprintf("%d", index))
	request.Header.Set("X-Total-Chunks", fmt.Sprintf("%d", total))
	setRegistryAuth(request, token)

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if (response.StatusCode >= 200 && response.StatusCode < 300) || conflictOK(response.StatusCode) {
		return nil
	}
	return fmt.Errorf("HTTP %d - %s", response.StatusCode, string(body))
}

// fileSHA256 hashes a file (the publish-existing-box path).
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
