package assets

import (
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
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Task operations (category artifact: one storage mutation at a time).
const (
	OpScan         = "artifact_scan"
	OpDownload     = "artifact_download"
	OpUpload       = "artifact_upload"
	OpMove         = "artifact_move"
	OpCopy         = "artifact_copy"
	OpDeleteFiles  = "artifact_delete_file"
	OpDeleteFolder = "artifact_delete_folder"
)

// ResourceAuth resolves a custom_resource_url secret's HTTP Basic
// credentials by name — SHI's downloadFileWithCustomResource path.
type ResourceAuth func(name string) (user, pass string, ok bool)

// ScanTaskMetadata is the artifact_scan task's metadata document.
type ScanTaskMetadata struct {
	ScanOptions
	// LocationID scans one location; empty scans all enabled (Type may then
	// narrow to one artifact type).
	LocationID string `json:"storage_location_id,omitempty"`
	Type       string `json:"type,omitempty"`
}

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

// TransferMetadata is the artifact_move/artifact_copy metadata document.
type TransferMetadata struct {
	ArtifactID    int64  `json:"artifact_id"`
	DestinationID string `json:"destination_storage_location_id"`
}

// DeleteFilesMetadata is the artifact_delete_file metadata document.
type DeleteFilesMetadata struct {
	ArtifactIDs []int64 `json:"artifact_ids"`
	DeleteFiles bool    `json:"delete_files"`
	Force       bool    `json:"force"`
}

// DeleteFolderMetadata is the artifact_delete_folder metadata document.
type DeleteFolderMetadata struct {
	LocationID      string `json:"storage_location_id"`
	Recursive       bool   `json:"recursive"`
	RemoveDBRecords bool   `json:"remove_db_records"`
	Force           bool   `json:"force"`
}

// RegisterExecutors wires the artifact operations into the task queue.
func RegisterExecutors(queue *tasks.Queue, store *Store, resourceAuth ResourceAuth, hcl HCLTokens, extensions map[string][]string) {
	if len(extensions) == 0 {
		extensions = DefaultExtensions()
	}
	e := &executors{queue: queue, store: store, resourceAuth: resourceAuth, hcl: hcl, extensions: extensions}
	queue.Register(OpScan, tasks.Executor{Run: e.scan})
	queue.Register(OpDownload, tasks.Executor{Run: e.download})
	queue.Register(OpUpload, tasks.Executor{Run: e.uploadProcess})
	queue.Register(OpMove, tasks.Executor{Run: e.move})
	queue.Register(OpCopy, tasks.Executor{Run: e.copyArtifact})
	queue.Register(OpDeleteFiles, tasks.Executor{Run: e.deleteFiles})
	queue.Register(OpDeleteFolder, tasks.Executor{Run: e.deleteFolder})
	queue.Register(OpHCLDownload, tasks.Executor{Run: e.hclDownload})
}

type executors struct {
	queue        *tasks.Queue
	store        *Store
	resourceAuth ResourceAuth
	hcl          HCLTokens
	extensions   map[string][]string
}

// progress records progress on the task row.
func (e *executors) progress(taskID string, percent float64, info map[string]any) {
	raw, err := json.Marshal(info)
	if err != nil {
		return
	}
	if uerr := e.queue.Store().UpdateProgress(context.Background(), taskID, percent, raw); uerr != nil {
		alog().Debug("progress update failed", "task_id", taskID, "error", uerr)
	}
}

func parseMetadata(task *tasks.Task, target any) error {
	if task.Metadata == nil {
		return errors.New(task.Operation + " task has no metadata")
	}
	if err := json.Unmarshal([]byte(*task.Metadata), target); err != nil {
		return fmt.Errorf("parse %s metadata: %w", task.Operation, err)
	}
	return nil
}

// scan runs a user-triggered scan (one location, one type, or everything).
func (e *executors) scan(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta ScanTaskMetadata
	if task.Metadata != nil {
		if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
			return fmt.Errorf("parse scan metadata: %w", err)
		}
	}

	locations := []*Location{}
	if meta.LocationID != "" {
		location, err := e.store.GetLocation(ctx, meta.LocationID)
		if err != nil {
			return err
		}
		locations = append(locations, location)
	} else {
		enabled := true
		list, err := e.store.ListLocations(ctx, &LocationFilter{Type: meta.Type, Enabled: &enabled})
		if err != nil {
			return err
		}
		locations = list
	}

	total := ScanResult{}
	failures := 0
	for _, location := range locations {
		out.Write("stdout", "Scanning "+location.Name+" ("+location.Path+")\n")
		result, err := e.store.ScanLocation(ctx, location, e.extensions[location.Type], &meta.ScanOptions, out.Write)
		if err != nil {
			failures++
			out.Write("stderr", location.Name+": "+err.Error()+"\n")
			continue
		}
		total.Scanned += result.Scanned
		total.Added += result.Added
		total.Removed += result.Removed
		total.Mismatched += result.Mismatched
		total.Missing += result.Missing
	}

	out.Write("stdout", fmt.Sprintf(
		"Scan complete: %d files scanned, %d added, %d removed, %d hash mismatches, %d missing across %d location(s)\n",
		total.Scanned, total.Added, total.Removed, total.Mismatched, total.Missing, len(locations)))
	if failures == len(locations) && len(locations) > 0 {
		return fmt.Errorf("all %d location(s) failed to scan", len(locations))
	}
	if total.Mismatched > 0 {
		return fmt.Errorf("%d file(s) fail hash verification", total.Mismatched)
	}
	return nil
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

// transferTarget resolves and validates a move/copy destination.
func (e *executors) transferTarget(ctx context.Context, meta *TransferMetadata) (*Artifact, *Location, string, error) {
	artifact, err := e.store.Get(ctx, meta.ArtifactID)
	if err != nil {
		return nil, nil, "", err
	}
	if !artifact.Exists || artifact.Path == "" {
		return nil, nil, "", errors.New("artifact has no file on disk")
	}
	destination, err := e.store.GetLocation(ctx, meta.DestinationID)
	if err != nil {
		return nil, nil, "", err
	}
	if destination.ID == artifact.LocationID {
		return nil, nil, "", errors.New("source and destination locations cannot be the same")
	}
	if destination.Type != artifact.Kind {
		return nil, nil, "", fmt.Errorf("artifact type %q does not match destination type %q",
			artifact.Kind, destination.Type)
	}
	target, err := PathFor(destination, artifact.Role, artifact.Filename)
	if err != nil {
		return nil, nil, "", err
	}
	if _, serr := os.Stat(target); serr == nil {
		return nil, nil, "", fmt.Errorf("destination already has %s", artifact.Filename)
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return nil, nil, "", merr
	}
	return artifact, destination, target, nil
}

// copyFile copies src to dst through the safe writer.
func copyFile(src, dst string) error {
	in, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	_, werr := safepath.WriteFileFrom(dst, in, 0o600)
	if cerr := in.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(dst)
	}
	return werr
}

// move relocates an artifact's file to another location of the same type
// (rename first; copy+delete across volumes) and rewrites its row.
func (e *executors) move(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta TransferMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	artifact, destination, target, err := e.transferTarget(ctx, &meta)
	if err != nil {
		return err
	}
	source := artifact.LocationID

	e.progress(task.ID, 30, map[string]any{"status": "moving_file"})
	out.Write("stdout", "Moving "+artifact.Path+" → "+target+"\n")
	if rerr := os.Rename(artifact.Path, target); rerr != nil {
		if cerr := copyFile(artifact.Path, target); cerr != nil {
			return cerr
		}
		if derr := os.Remove(artifact.Path); derr != nil {
			out.Write("stderr", "source removal after copy failed: "+derr.Error()+"\n")
		}
	}

	e.progress(task.ID, 70, map[string]any{"status": "updating_database_records"})
	if uerr := e.store.UpdatePlacement(ctx, artifact.ID, destination.ID, target); uerr != nil {
		return uerr
	}
	for _, id := range []string{source, destination.ID} {
		if id == "" {
			continue
		}
		if rerr := e.store.RefreshLocationStats(ctx, id); rerr != nil {
			out.Write("stderr", "location stats refresh failed: "+rerr.Error()+"\n")
		}
	}
	out.Write("stdout", "Moved "+artifact.Filename+" to "+destination.Name+"\n")
	return nil
}

// copyArtifact duplicates an artifact's file into another location of the
// same type and registers the copy as a new row.
func (e *executors) copyArtifact(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta TransferMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	artifact, destination, target, err := e.transferTarget(ctx, &meta)
	if err != nil {
		return err
	}

	e.progress(task.ID, 30, map[string]any{"status": "copying_file"})
	out.Write("stdout", "Copying "+artifact.Path+" → "+target+"\n")
	if cerr := copyFile(artifact.Path, target); cerr != nil {
		return cerr
	}

	e.progress(task.ID, 70, map[string]any{"status": "creating_new_database_record"})
	duplicate, err := e.store.RecordIngested(ctx, &Ingested{
		LocationID: destination.ID, Role: artifact.Role, Kind: artifact.Kind,
		Filename: artifact.Filename, Path: target, SHA256: artifact.SHA256,
		Size: artifact.Size, Version: artifact.Version, SourceURL: artifact.SourceURL,
	})
	if err != nil {
		return err
	}
	if rerr := e.store.RefreshLocationStats(ctx, destination.ID); rerr != nil {
		out.Write("stderr", "location stats refresh failed: "+rerr.Error()+"\n")
	}
	out.Write("stdout", fmt.Sprintf("Copied %s to %s (artifact %d)\n",
		artifact.Filename, destination.Name, duplicate.ID))
	return nil
}

// deleteFiles removes artifact rows (and their files when delete_files).
func (e *executors) deleteFiles(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta DeleteFilesMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	if len(meta.ArtifactIDs) == 0 {
		return errors.New("artifact_ids is empty")
	}

	deleted, errorsCount := 0, 0
	locations := map[string]bool{}
	for _, id := range meta.ArtifactIDs {
		artifact, err := e.store.Get(ctx, id)
		if errors.Is(err, ErrNotFound) {
			out.Write("stderr", fmt.Sprintf("artifact %d not found — skipped\n", id))
			errorsCount++
			continue
		}
		if err != nil {
			return err
		}
		if meta.DeleteFiles && artifact.Path != "" {
			if rerr := os.Remove(artifact.Path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				out.Write("stderr", artifact.Filename+": file removal failed ("+rerr.Error()+")\n")
				if !meta.Force {
					errorsCount++
					continue
				}
			}
		}
		if derr := e.store.DeleteRow(ctx, artifact.ID); derr != nil {
			return derr
		}
		deleted++
		if artifact.LocationID != "" {
			locations[artifact.LocationID] = true
		}
		out.Write("stdout", "Deleted "+artifact.Filename+"\n")
	}
	for id := range locations {
		if rerr := e.store.RefreshLocationStats(ctx, id); rerr != nil {
			out.Write("stderr", "location stats refresh failed: "+rerr.Error()+"\n")
		}
	}

	out.Write("stdout", fmt.Sprintf("Deleted %d/%d artifact(s)\n", deleted, len(meta.ArtifactIDs)))
	if deleted == 0 {
		return errors.New("no artifacts were deleted")
	}
	return nil
}

// deleteFolder empties a storage location (contents only, zoneweaver's rule)
// and removes its rows — then the location row itself.
func (e *executors) deleteFolder(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta DeleteFolderMetadata
	if err := parseMetadata(task, &meta); err != nil {
		return err
	}
	location, err := e.store.GetLocation(ctx, meta.LocationID)
	if err != nil {
		return err
	}

	if meta.RemoveDBRecords {
		rows, lerr := e.store.ListByLocation(ctx, location.ID)
		if lerr != nil {
			return lerr
		}
		out.Write("stdout", fmt.Sprintf("Removing %d artifact record(s)\n", len(rows)))
	}

	if meta.Recursive {
		entries, rerr := os.ReadDir(location.Path)
		if rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return rerr
		}
		for _, entry := range entries {
			path := filepath.Join(location.Path, entry.Name())
			if derr := os.RemoveAll(path); derr != nil {
				out.Write("stderr", path+": removal failed ("+derr.Error()+")\n")
				if !meta.Force {
					return derr
				}
			}
		}
		out.Write("stdout", "Folder contents deleted\n")
	}

	if derr := e.store.DeleteLocation(ctx, location.ID); derr != nil {
		return derr
	}
	out.Write("stdout", "Storage location "+location.Name+" removed\n")
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
