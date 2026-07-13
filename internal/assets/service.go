package assets

import (
	"context"
	"crypto/md5" // #nosec G501 -- change-detection fingerprint only (zoneweaver's config_hash), never security
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// PathConfig is one artifact_storage.paths[] entry.
type PathConfig struct {
	Name    string
	Path    string
	Type    string
	Enabled bool
}

// ServiceConfig wires the storage service.
type ServiceConfig struct {
	Enabled bool
	// Root hosts the built-in locations (<root>/isos, images, installers,
	// fixpacks, hotfixes).
	Root string
	// Paths are the operator's own locations (artifact_storage.paths[]).
	Paths []PathConfig
	// Extensions filter iso/image scans per type
	// (artifact_storage.scanning.supported_extensions).
	Extensions map[string][]string
	// ScanInterval is seconds between periodic direct scans (0 disables).
	ScanInterval int
}

// builtinLocations are the always-present locations under the root — the
// five types out of the box, one location each.
var builtinLocations = []struct {
	dir  string
	name string
	kind string
}{
	{"isos", "ISO Storage", KindISO},
	{"images", "Image Storage", KindImage},
	{"installers", "Installer Cache", KindInstaller},
	{"fixpacks", "Fixpack Cache", KindFixpack},
	{"hotfixes", "Hotfix Cache", KindHotfix},
}

// DefaultExtensions is the scanning filter fallback (zoneweaver's
// supported_extensions defaults).
func DefaultExtensions() map[string][]string {
	return map[string][]string{
		KindISO:   {".iso"},
		KindImage: {".vmdk", ".raw", ".vdi", ".qcow2", ".img", ".ova", ".ovf"},
	}
}

// Service manages the storage locations: config↔database sync, built-in
// seeding, orphan-row adoption, expectation seeding, and the startup +
// periodic direct scans (zoneweaver's ArtifactStorageService — no task rows
// for automatic scans; user-triggered scans stay tasks).
type Service struct {
	store *Store
	cfg   ServiceConfig

	mu          sync.Mutex
	scanning    bool
	running     bool
	initialized bool
	stop        chan struct{}

	statsMu        sync.Mutex
	scanRuns       int
	scanErrors     int
	lastScanOK     *time.Time
	locationsCount int
}

// NewService builds the storage service.
func NewService(store *Store, cfg ServiceConfig) *Service {
	if len(cfg.Extensions) == 0 {
		cfg.Extensions = DefaultExtensions()
	}
	return &Service{store: store, cfg: cfg}
}

// configHash fingerprints one path entry for change detection.
func configHash(p *PathConfig) string {
	raw, _ := json.Marshal(map[string]any{
		"name": p.Name, "path": p.Path, "type": p.Type, "enabled": p.Enabled,
	})
	sum := md5.Sum(raw) // #nosec G401 -- fingerprint, not security
	return hex.EncodeToString(sum[:])
}

// SyncLocations converges the database onto the built-in set plus the
// configured paths: directories are created, entries upserted by path, and
// config-sourced rows dropped from configuration are removed (their artifact
// rows with them — the files stay on disk).
func (s *Service) SyncLocations(ctx context.Context) error {
	keepPaths := map[string]bool{}

	for _, builtin := range builtinLocations {
		path := filepath.Join(s.cfg.Root, builtin.dir)
		keepPaths[path] = true
		if err := s.ensureLocation(ctx, &PathConfig{
			Name: builtin.name, Path: path, Type: builtin.kind, Enabled: true,
		}, "builtin"); err != nil {
			return err
		}
	}

	for i := range s.cfg.Paths {
		entry := s.cfg.Paths[i]
		clean, err := safepath.CleanAbs(entry.Path)
		if err != nil {
			alog().Warn("invalid artifact_storage path — skipped", "name", entry.Name, "path", entry.Path, "error", err)
			continue
		}
		entry.Path = clean
		keepPaths[clean] = true
		if err := s.ensureLocation(ctx, &entry, "config"); err != nil {
			return err
		}
	}

	// Remove config-sourced rows no longer configured; builtins never leave.
	locations, err := s.store.ListLocations(ctx, &LocationFilter{})
	if err != nil {
		return err
	}
	kept := 0
	for _, location := range locations {
		if keepPaths[location.Path] {
			kept++
			continue
		}
		if location.Source == "builtin" {
			kept++
			continue
		}
		alog().Info("removing storage location no longer in config",
			"name", location.Name, "path", location.Path)
		if derr := s.store.DeleteLocation(ctx, location.ID); derr != nil {
			return derr
		}
	}

	s.statsMu.Lock()
	s.locationsCount = kept
	s.statsMu.Unlock()
	return nil
}

// ensureLocation upserts one location by path, creating its directory. A
// directory that cannot be created disables the location instead of failing
// the sync (zoneweaver's rule).
func (s *Service) ensureLocation(ctx context.Context, entry *PathConfig, source string) error {
	enabled := entry.Enabled
	if err := os.MkdirAll(entry.Path, 0o750); err != nil {
		alog().Warn("storage directory cannot be created — location disabled",
			"name", entry.Name, "path", entry.Path, "error", err)
		enabled = false
	}
	hash := configHash(entry)

	existing, err := s.store.FindLocationByPath(ctx, entry.Path)
	switch {
	case err == nil:
		if existing.ConfigHash == hash && existing.Enabled == enabled &&
			existing.Name == entry.Name {
			return nil
		}
		enabledCopy := enabled
		name := entry.Name
		if _, uerr := s.store.UpdateLocation(ctx, existing.ID, &name, &enabledCopy); uerr != nil {
			return uerr
		}
		_, uerr := s.store.db.ExecContext(ctx, `UPDATE artifact_locations
			SET type = ?, source = ?, config_hash = ?, updated_at = ? WHERE id = ?`,
			entry.Type, source, hash, formatTime(time.Now()), existing.ID)
		return uerr
	case errors.Is(err, ErrLocationNotFound):
		_, cerr := s.store.CreateLocation(ctx, &NewLocation{
			Name: entry.Name, Path: entry.Path, Type: entry.Type,
			Enabled: enabled, Source: source, ConfigHash: hash,
		})
		return cerr
	default:
		return err
	}
}

// Initialize converges locations, adopts pre-merge rows, and seeds the
// bundled hash expectations. Safe to call once at startup.
func (s *Service) Initialize(ctx context.Context) error {
	if !s.cfg.Enabled {
		alog().Info("artifact storage is disabled")
		return nil
	}
	if err := s.SyncLocations(ctx); err != nil {
		return fmt.Errorf("sync storage locations: %w", err)
	}
	if err := s.store.AdoptOrphanRows(ctx); err != nil {
		return fmt.Errorf("adopt pre-merge artifact rows: %w", err)
	}
	if err := SeedExpectations(ctx, s.store); err != nil {
		return err
	}
	s.mu.Lock()
	s.initialized = true
	s.mu.Unlock()
	return nil
}

// Start kicks off the startup scan and the periodic scan loop.
func (s *Service) Start() {
	if !s.cfg.Enabled {
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stop = make(chan struct{})
	stop := s.stop
	s.mu.Unlock()

	go s.runScanAll("initial_scan")

	if s.cfg.ScanInterval > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(s.cfg.ScanInterval) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					s.runScanAll("periodic_scan")
				}
			}
		}()
	}
	alog().Info("artifact storage service started", "scan_interval_seconds", s.cfg.ScanInterval)
}

// Stop ends the periodic loop.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stop)
	s.running = false
}

// runScanAll direct-scans every enabled location, in-flight guarded so a
// slow scan never stacks behind itself.
func (s *Service) runScanAll(source string) {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return
	}
	s.scanning = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	enabled := true
	locations, err := s.store.ListLocations(ctx, &LocationFilter{Enabled: &enabled})
	if err != nil {
		alog().Error("artifact scan failed", "source", source, "error", err)
		return
	}
	failures := 0
	for _, location := range locations {
		// Automatic scans clean orphaned records (zoneweaver's rule) and
		// never re-hash known files.
		opts := &ScanOptions{RemoveOrphaned: true}
		if _, serr := s.store.ScanLocation(ctx, location, s.cfg.Extensions[location.Type], opts, nil); serr != nil {
			failures++
			alog().Warn("storage location scan failed", "location", location.Name, "error", serr)
		}
	}

	now := time.Now()
	s.statsMu.Lock()
	s.scanRuns++
	s.scanErrors += failures
	if failures == 0 {
		s.lastScanOK = &now
	}
	s.locationsCount = len(locations)
	s.statsMu.Unlock()
}

// Status answers GET /artifacts/service/status (zoneweaver's getStatus
// shape).
func (s *Service) Status() map[string]any {
	s.mu.Lock()
	running, initialized, scanning := s.running, s.initialized, s.scanning
	s.mu.Unlock()
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	var lastScan any
	if s.lastScanOK != nil {
		lastScan = s.lastScanOK.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"isRunning":     running,
		"isInitialized": initialized,
		"isScanning":    scanning,
		"config": map[string]any{
			"enabled":           s.cfg.Enabled,
			"scanning_interval": s.cfg.ScanInterval,
			"paths_configured":  len(s.cfg.Paths),
		},
		"stats": map[string]any{
			"scanRuns":         s.scanRuns,
			"lastScanSuccess":  lastScan,
			"totalScanErrors":  s.scanErrors,
			"locationsManaged": s.locationsCount,
		},
		"activeIntervals": map[string]any{
			"periodicScan": running && s.cfg.ScanInterval > 0,
		},
	}
}
