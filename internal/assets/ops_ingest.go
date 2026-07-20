package assets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// DownloadMetadata is the artifact_download task's metadata document
// (zoneweaver's downloadFromUrl body).
type DownloadMetadata struct {
	URL        string `json:"url"`
	LocationID string `json:"storage_location_id"`
	// Role is required when the destination is a role-keyed location.
	Role     string `json:"role,omitempty"`
	Filename string `json:"filename,omitempty"`
	// Checksum is the expected SHA-256 (the system's one algorithm); a
	// mismatch discards the download.
	Checksum          string `json:"checksum,omitempty"`
	OverwriteExisting bool   `json:"overwrite_existing,omitempty"`
	// ResourceName names a custom_resource_url secret whose Basic-auth pair
	// authenticates the download; credentials never enter task metadata.
	ResourceName string `json:"resource_name,omitempty"`
}

// Validate checks a download request before it becomes a task.
func (m *DownloadMetadata) Validate() error {
	parsed, err := url.Parse(m.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("url must be an http(s) URL")
	}
	if m.LocationID == "" {
		return errors.New("storage_path_id is required")
	}
	if m.Filename == "" {
		m.Filename = filepath.Base(parsed.Path)
	}
	if !ValidFilename(m.Filename) {
		return errors.New("filename is not usable (set filename explicitly)")
	}
	if m.Checksum != "" && !isHexSHA256(m.Checksum) {
		return errors.New("checksum must be a 64-character hex SHA-256 digest")
	}
	return nil
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// download streams a URL into a location: temp file, SHA-256 computed DURING
// the stream, verify-then-promote (a mismatch deletes the temp file and
// fails — never promoted, no auto-retry; SHI's exact rules).
func (e *executors) download(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta DownloadMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	if err := meta.Validate(); err != nil {
		return err
	}

	location, err := e.store.GetLocation(ctx, meta.LocationID)
	if err != nil {
		return err
	}
	if !location.Enabled {
		return errors.New("storage location is disabled")
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

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.URL, http.NoBody)
	if err != nil {
		return err
	}
	if meta.ResourceName != "" {
		user, pass, ok := e.resourceAuth(meta.ResourceName)
		if !ok {
			return errors.New("no custom resource credentials named " + meta.ResourceName + " in the secrets store")
		}
		request.SetBasicAuth(user, pass)
	}

	out.Write("stdout", "Downloading "+meta.URL+"\n")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %s", response.Status)
	}

	temp := target + ".download"
	sha, size, err := e.streamToFile(task.ID, response.Body, temp, response.ContentLength)
	if err != nil {
		_ = os.Remove(temp)
		return err
	}
	if meta.Checksum != "" && !strings.EqualFold(sha, meta.Checksum) {
		_ = os.Remove(temp)
		return fmt.Errorf("hash mismatch: downloaded %s, expected %s — file discarded", sha, meta.Checksum)
	}
	if rerr := os.Rename(temp, target); rerr != nil {
		_ = os.Remove(temp)
		return rerr
	}
	if meta.Checksum != "" {
		if serr := e.store.SetExpectation(ctx, location.ID, meta.Role, location.Type, meta.Filename, meta.Checksum); serr != nil {
			out.Write("stderr", "record expectation failed: "+serr.Error()+"\n")
		}
	}
	artifact, err := e.store.RecordIngested(ctx, &Ingested{
		LocationID: location.ID, Role: meta.Role, Kind: location.Type,
		Filename: meta.Filename, Path: target, SHA256: sha, Size: size, SourceURL: meta.URL,
	})
	if err != nil {
		return err
	}
	if rerr := e.store.RefreshLocationStats(ctx, location.ID); rerr != nil {
		out.Write("stderr", "location stats refresh failed: "+rerr.Error()+"\n")
	}
	if !artifact.Verified() {
		return fmt.Errorf("hash mismatch against recorded expectation: %s != %s",
			artifact.SHA256, artifact.ExpectedSHA256)
	}
	out.Write("stdout", "Downloaded and verified "+artifact.Filename+" ("+sha+", "+
		strconv.FormatInt(size, 10)+" bytes)\n")
	return nil
}

// streamToFile lands the body at path through the shared streaming writer,
// hashing as it goes and reporting progress roughly once per second.
func (e *executors) streamToFile(taskID string, body io.Reader, path string, total int64) (sha string, size int64, err error) {
	hasher := sha256.New()
	counter := &progressReader{
		reader: io.TeeReader(body, hasher),
		total:  total,
		start:  time.Now(),
		report: func(written, totalBytes int64, elapsed time.Duration) {
			e.reportDownloadProgress(taskID, written, totalBytes, elapsed)
		},
	}
	written, err := safepath.WriteFileFrom(path, counter, 0o600)
	if err != nil {
		return "", 0, err
	}
	e.reportDownloadProgress(taskID, written, total, time.Since(counter.start))
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

// progressReader counts bytes flowing through a download and fires the
// report callback about once per second.
type progressReader struct {
	reader     io.Reader
	total      int64
	start      time.Time
	lastReport time.Time
	written    int64
	report     func(written, total int64, elapsed time.Duration)
}

func (p *progressReader) Read(buffer []byte) (int, error) {
	n, err := p.reader.Read(buffer)
	p.written += int64(n)
	if now := time.Now(); now.Sub(p.lastReport) >= time.Second {
		p.lastReport = now
		p.report(p.written, p.total, now.Sub(p.start))
	}
	return n, err
}

// reportDownloadProgress emits the shared download progress document.
func (e *executors) reportDownloadProgress(taskID string, written, total int64, elapsed time.Duration) {
	const mb = 1024 * 1024
	info := map[string]any{
		"downloaded_mb": float64(written) / mb,
		"status":        "downloading",
	}
	percent := -1.0
	seconds := elapsed.Seconds()
	speed := 0.0
	if seconds > 0 {
		speed = float64(written) * 8 / mb / seconds
		info["speed_mbps"] = speed
	}
	if total > 0 {
		info["total_mb"] = float64(total) / mb
		percent = float64(written) / float64(total) * 95
		if speed > 0 && written < total {
			remaining := float64(total-written) * 8 / mb
			info["eta_seconds"] = int64(remaining / speed)
		}
	}
	e.progress(taskID, percent, info)
}

// UploadMetadata is the artifact_upload task's metadata: written by
// prepare, completed by the upload handler (final_path/upload_completed),
// consumed by the executor once the task flips prepared→pending.
type UploadMetadata struct {
	OriginalName      string `json:"original_name"`
	Size              int64  `json:"size"`
	LocationID        string `json:"storage_location_id"`
	Role              string `json:"role,omitempty"`
	Checksum          string `json:"checksum,omitempty"`
	OverwriteExisting bool   `json:"overwrite_existing,omitempty"`
	FinalPath         string `json:"final_path,omitempty"`
	UploadCompleted   bool   `json:"upload_completed,omitempty"`
}

// uploadProcess finishes an upload the HTTP handler already landed at its
// final path: hash, verify a user-supplied checksum (mismatch deletes the
// file and fails), register.
func (e *executors) uploadProcess(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta UploadMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	if !meta.UploadCompleted || meta.FinalPath == "" {
		return errors.New("upload task has no completed file to process")
	}
	location, err := e.store.GetLocation(ctx, meta.LocationID)
	if err != nil {
		return err
	}

	e.progress(task.ID, 50, map[string]any{"status": "calculating_checksum"})
	sha, size, err := HashFile(meta.FinalPath)
	if err != nil {
		return fmt.Errorf("hash uploaded file: %w", err)
	}
	if meta.Checksum != "" && !strings.EqualFold(sha, meta.Checksum) {
		_ = os.Remove(meta.FinalPath)
		return fmt.Errorf("checksum verification failed: expected %s, got %s — file discarded", meta.Checksum, sha)
	}
	if meta.Checksum != "" {
		if serr := e.store.SetExpectation(ctx, location.ID, meta.Role, location.Type, meta.OriginalName, meta.Checksum); serr != nil {
			out.Write("stderr", "record expectation failed: "+serr.Error()+"\n")
		}
	}

	e.progress(task.ID, 80, map[string]any{"status": "registering"})
	artifact, err := e.store.RecordIngested(ctx, &Ingested{
		LocationID: location.ID, Role: meta.Role, Kind: location.Type,
		Filename: meta.OriginalName, Path: meta.FinalPath, SHA256: sha, Size: size,
	})
	if err != nil {
		return err
	}
	if rerr := e.store.RefreshLocationStats(ctx, location.ID); rerr != nil {
		out.Write("stderr", "location stats refresh failed: "+rerr.Error()+"\n")
	}
	if !artifact.Verified() {
		return fmt.Errorf("hash mismatch against recorded expectation: %s != %s",
			artifact.SHA256, artifact.ExpectedSHA256)
	}
	out.Write("stdout", "Processed upload "+artifact.Filename+" ("+sha+", "+
		strconv.FormatInt(size, 10)+" bytes)\n")
	return nil
}

// IngestReader streams content into a location — the upload landing path:
// temp file through the shared writer, hash, rename into place, register.
func (s *Store) IngestReader(ctx context.Context, location *Location, role, filename string, r io.Reader) (*Artifact, error) {
	target, err := PathFor(location, role, filename)
	if err != nil {
		return nil, err
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return nil, merr
	}
	temp := target + ".upload"
	if _, werr := safepath.WriteFileFrom(temp, r, 0o600); werr != nil {
		_ = os.Remove(temp)
		return nil, werr
	}
	sha, size, err := HashFile(temp)
	if err != nil {
		_ = os.Remove(temp)
		return nil, err
	}
	if rerr := os.Rename(temp, target); rerr != nil {
		_ = os.Remove(temp)
		return nil, rerr
	}
	artifact, err := s.RecordIngested(ctx, &Ingested{
		LocationID: location.ID, Role: role, Kind: location.Type,
		Filename: filename, Path: target, SHA256: sha, Size: size,
	})
	if err != nil {
		return nil, err
	}
	_ = s.RefreshLocationStats(ctx, location.ID)
	return artifact, nil
}

// Ingest hashes an existing agent-host file into a location — the
// register-local-path flow (SHI's add-file picker). source may already BE
// the canonical path.
func (s *Store) Ingest(ctx context.Context, location *Location, role, filename, source string, move bool) (*Artifact, error) {
	target, err := PathFor(location, role, filename)
	if err != nil {
		return nil, err
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return nil, merr
	}

	if source != target {
		if cerr := copyFile(source, target); cerr != nil {
			return nil, cerr
		}
		if move {
			if rerr := os.Remove(source); rerr != nil {
				alog().Warn("remove source after move", "path", source, "error", rerr)
			}
		}
	}

	sha, size, err := HashFile(target)
	if err != nil {
		return nil, err
	}
	artifact, err := s.RecordIngested(ctx, &Ingested{
		LocationID: location.ID, Role: role, Kind: location.Type,
		Filename: filename, Path: target, SHA256: sha, Size: size,
	})
	if err != nil {
		return nil, err
	}
	_ = s.RefreshLocationStats(ctx, location.ID)
	return artifact, nil
}

// LandUpload streams a request body part to its final location path through
// a temp file — the POST /artifacts/upload/{taskId} handler's write half;
// the artifact_upload executor hashes and registers afterwards.
func LandUpload(location *Location, role, filename string, r io.Reader, overwrite bool) (path string, size int64, err error) {
	target, err := PathFor(location, role, filename)
	if err != nil {
		return "", 0, err
	}
	if !overwrite {
		if _, serr := os.Stat(target); serr == nil {
			return "", 0, fmt.Errorf("file already exists: %s (set overwrite_existing at prepare)", filename)
		}
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return "", 0, merr
	}
	temp := target + ".upload"
	size, err = safepath.WriteFileFrom(temp, r, 0o600)
	if err != nil {
		_ = os.Remove(temp)
		return "", 0, err
	}
	if rerr := os.Rename(temp, target); rerr != nil {
		_ = os.Remove(temp)
		return "", 0, rerr
	}
	return target, size, nil
}
