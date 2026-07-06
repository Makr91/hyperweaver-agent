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

// Task operations (category artifact: one cache mutation at a time).
const (
	OpScan     = "artifact_scan"
	OpDownload = "artifact_download"
)

// ResourceAuth resolves a custom_resource_url secret's HTTP Basic
// credentials by name — SHI's downloadFileWithCustomResource path; ok is
// false when the entry is absent or carries no auth.
type ResourceAuth func(name string) (user, pass string, ok bool)

// DownloadMetadata is the artifact_download task's metadata document.
type DownloadMetadata struct {
	URL            string `json:"url"`
	Role           string `json:"role"`
	Kind           string `json:"kind"`
	Filename       string `json:"filename,omitempty"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	// ResourceName names a custom_resource_url secret whose Basic-auth pair
	// authenticates the download; the credentials never enter task metadata.
	ResourceName string `json:"resource_name,omitempty"`
}

// Validate checks a download request before it becomes a task.
func (m *DownloadMetadata) Validate() error {
	parsed, err := url.Parse(m.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("url must be an http(s) URL")
	}
	if !ValidRole(m.Role) {
		return errors.New("role is not usable")
	}
	if !ValidKind(m.Kind) {
		return errors.New("kind must be installer, fixpack, or hotfix")
	}
	if m.Filename == "" {
		m.Filename = filepath.Base(parsed.Path)
	}
	if !ValidFilename(m.Filename) {
		return errors.New("filename is not usable (set filename explicitly)")
	}
	if m.ExpectedSHA256 != "" && !isHexSHA256(m.ExpectedSHA256) {
		return errors.New("expected_sha256 must be a 64-character hex digest")
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

// ScanMetadata is the artifact_scan task's metadata document.
type ScanMetadata struct {
	// VerifyChecksums re-hashes every present file (otherwise existence and
	// size refresh only — SHI's verifyCache did existence-only).
	VerifyChecksums bool `json:"verify_checksums"`
}

// RegisterExecutors wires the artifact operations into the task queue.
func RegisterExecutors(queue *tasks.Queue, store *Store, resourceAuth ResourceAuth, hcl HCLTokens) {
	e := &executors{queue: queue, store: store, resourceAuth: resourceAuth, hcl: hcl}
	queue.Register(OpScan, tasks.Executor{Run: e.scan})
	queue.Register(OpDownload, tasks.Executor{Run: e.download})
	queue.Register(OpHCLDownload, tasks.Executor{Run: e.hclDownload})
}

type executors struct {
	queue        *tasks.Queue
	store        *Store
	resourceAuth ResourceAuth
	hcl          HCLTokens
}

// progress records download progress on the task row (zoneweaver's
// download-progress document: downloaded_mb/total_mb/speed_mbps/eta_seconds,
// with the task id passed down properly — never re-found by URL substring).
func (e *executors) progress(taskID string, percent float64, info map[string]any) {
	raw, err := json.Marshal(info)
	if err != nil {
		return
	}
	if uerr := e.queue.Store().UpdateProgress(context.Background(), taskID, percent, raw); uerr != nil {
		alog().Debug("progress update failed", "task_id", taskID, "error", uerr)
	}
}

// scan walks the cache root and reconciles rows with reality: new files are
// hashed and registered, present rows refreshed (re-hashed when
// verify_checksums), vanished files marked missing — expectations survive.
func (e *executors) scan(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta ScanMetadata
	if task.Metadata != nil {
		if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
			return fmt.Errorf("parse scan metadata: %w", err)
		}
	}

	known, err := e.store.List(ctx, &ListFilter{})
	if err != nil {
		return err
	}
	knownByPath := make(map[string]*Artifact, len(known))
	for _, artifact := range known {
		if artifact.Path != "" {
			knownByPath[artifact.Path] = artifact
		}
	}

	found := map[string]bool{}
	registered, verified, mismatched := 0, 0, 0
	roles, _ := os.ReadDir(e.store.Dir())
	for _, roleEntry := range roles {
		if !roleEntry.IsDir() || !ValidRole(roleEntry.Name()) {
			continue
		}
		for _, kind := range []string{KindInstaller, KindFixpack, KindHotfix} {
			kindDir := filepath.Join(e.store.Dir(), roleEntry.Name(), CacheSubdir(kind))
			files, derr := os.ReadDir(kindDir)
			if derr != nil {
				continue
			}
			for _, file := range files {
				if file.IsDir() || !ValidFilename(file.Name()) {
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				path := filepath.Join(kindDir, file.Name())
				found[path] = true
				existing := knownByPath[path]
				if existing != nil && existing.Exists && !meta.VerifyChecksums {
					continue
				}
				sha, size, herr := HashFile(path)
				if herr != nil {
					out.Write("stderr", path+": hash failed ("+herr.Error()+")\n")
					continue
				}
				artifact, rerr := e.store.RecordIngested(ctx, &Ingested{
					Role: roleEntry.Name(), Kind: kind, Filename: file.Name(),
					Path: path, SHA256: sha, Size: size,
				})
				if rerr != nil {
					out.Write("stderr", path+": registry update failed ("+rerr.Error()+")\n")
					continue
				}
				switch {
				case existing == nil:
					registered++
					out.Write("stdout", "Registered "+artifact.Role+"/"+kind+"/"+artifact.Filename+" ("+sha+")\n")
				case artifact.Verified():
					verified++
				default:
					mismatched++
					out.Write("stderr", "HASH MISMATCH "+artifact.Role+"/"+kind+"/"+artifact.Filename+
						": file "+artifact.SHA256+" != expected "+artifact.ExpectedSHA256+"\n")
				}
			}
		}
	}

	missing := 0
	for _, artifact := range known {
		if artifact.Path != "" && artifact.Exists && !found[artifact.Path] {
			if merr := e.store.MarkMissing(ctx, artifact.ID); merr != nil {
				out.Write("stderr", artifact.Filename+": mark missing failed ("+merr.Error()+")\n")
				continue
			}
			missing++
			out.Write("stderr", artifact.Role+"/"+artifact.Kind+"/"+artifact.Filename+" is gone — marked missing (expectation kept)\n")
		}
	}

	out.Write("stdout", fmt.Sprintf(
		"Scan complete: %d newly registered, %d verified, %d hash mismatches, %d missing\n",
		registered, verified, mismatched, missing))
	if mismatched > 0 {
		return fmt.Errorf("%d cached file(s) fail hash verification", mismatched)
	}
	return nil
}

// download streams a URL into the cache: temp .download file, SHA-256
// computed DURING the stream, verify-then-promote (a mismatch deletes the
// temp file and fails — never promoted, no auto-retry; SHI's exact rules).
func (e *executors) download(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta DownloadMetadata
	if task.Metadata == nil {
		return errors.New("download task has no metadata")
	}
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse download metadata: %w", err)
	}
	if err := meta.Validate(); err != nil {
		return err
	}

	target, err := e.store.PathFor(meta.Role, meta.Kind, meta.Filename)
	if err != nil {
		return err
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

	if meta.ExpectedSHA256 != "" && !strings.EqualFold(sha, meta.ExpectedSHA256) {
		_ = os.Remove(temp)
		return fmt.Errorf("hash mismatch: downloaded %s, expected %s — file discarded", sha, meta.ExpectedSHA256)
	}
	if rerr := os.Rename(temp, target); rerr != nil {
		_ = os.Remove(temp)
		return rerr
	}
	if meta.ExpectedSHA256 != "" {
		if serr := e.store.SetExpectation(ctx, meta.Role, meta.Kind, meta.Filename, meta.ExpectedSHA256); serr != nil {
			out.Write("stderr", "record expectation failed: "+serr.Error()+"\n")
		}
	}
	artifact, err := e.store.RecordIngested(ctx, &Ingested{
		Role: meta.Role, Kind: meta.Kind, Filename: meta.Filename,
		Path: target, SHA256: sha, Size: size, SourceURL: meta.URL,
	})
	if err != nil {
		return err
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
// hashing as it goes and reporting progress on the task row roughly once per
// second.
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

// IngestReader streams content into the cache under (role, kind, filename)
// — the browser-upload path: land in a temp file through the shared writer,
// hash it, rename into place, register.
func (s *Store) IngestReader(ctx context.Context, role, kind, filename string, r io.Reader) (*Artifact, error) {
	target, err := s.PathFor(role, kind, filename)
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
	return s.RecordIngested(ctx, &Ingested{
		Role: role, Kind: kind, Filename: filename,
		Path: target, SHA256: sha, Size: size,
	})
}

// Ingest hashes an existing file into the cache under (role, kind): the
// register-local-path flow (SHI's add-file picker). source may already BE
// the cache path (a scan-less quick registration).
func (s *Store) Ingest(ctx context.Context, role, kind, filename, source string, move bool) (*Artifact, error) {
	target, err := s.PathFor(role, kind, filename)
	if err != nil {
		return nil, err
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return nil, merr
	}

	if source != target {
		src, oerr := os.Open(filepath.Clean(source))
		if oerr != nil {
			return nil, oerr
		}
		_, werr := safepath.WriteFileFrom(target, src, 0o600)
		if cerr := src.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, werr
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
	return s.RecordIngested(ctx, &Ingested{
		Role: role, Kind: kind, Filename: filename,
		Path: target, SHA256: sha, Size: size,
	})
}
