package assets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	if len(task.Metadata) == 0 {
		return errors.New(task.Operation + " task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, target); err != nil {
		return fmt.Errorf("parse %s metadata: %w", task.Operation, err)
	}
	return nil
}

// scan runs a user-triggered scan (one location, one type, or everything).
func (e *executors) scan(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta ScanTaskMetadata
	if len(task.Metadata) > 0 {
		if err := json.Unmarshal(task.Metadata, &meta); err != nil {
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
