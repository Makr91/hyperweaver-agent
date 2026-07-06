package monitoring

import (
	"context"
	"sync"
	"time"
)

// Service is the monitoring facade the HTTP surface talks to: the live
// sampler always; the store and collector only when monitoring.storage_enabled.
// The one-struct split keeps the handlers mode-blind — they ask for history
// and get either stored rows or the single live sample.
type Service struct {
	sampler  *Sampler
	store    *Store // nil when storage is disabled
	interval time.Duration
	retain   time.Duration

	mu           sync.Mutex
	running      bool
	stopCh       chan struct{}
	done         chan struct{}
	startedAt    time.Time
	lastRun      time.Time
	lastError    string
	samplesTaken int64
	errorCount   int64
}

// NewService builds the facade. store may be nil (realtime-only mode).
func NewService(sampler *Sampler, store *Store, collectionInterval time.Duration, retentionDays int) *Service {
	return &Service{
		sampler:  sampler,
		store:    store,
		interval: collectionInterval,
		retain:   time.Duration(retentionDays) * 24 * time.Hour,
	}
}

// Sampler exposes the live sampler (the realtime paths and /stats-adjacent
// consumers).
func (s *Service) Sampler() *Sampler {
	return s.sampler
}

// StorageEnabled reports whether samples persist (drives the sampling
// metadata the endpoints answer with).
func (s *Service) StorageEnabled() bool {
	return s.store != nil
}

// Store returns the telemetry store, nil in realtime-only mode.
func (s *Service) Store() *Store {
	return s.store
}

// Start launches the collector loop. No-op in realtime-only mode.
func (s *Service) Start() {
	if s.store == nil {
		monlog().Info("monitoring storage disabled; /monitoring serves realtime samples only")
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.startedAt = time.Now()
	s.stopCh = make(chan struct{})
	s.done = make(chan struct{})
	s.mu.Unlock()

	monlog().Info("monitoring collector started",
		"interval", s.interval, "retention", s.retain)
	go s.loop()
}

// Stop halts the collector loop. No-op when not running.
func (s *Service) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()
	<-s.done
	monlog().Info("monitoring collector stopped")
}

// Running reports whether the collector loop is active.
func (s *Service) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Stats returns the collector's bookkeeping for /monitoring/status.
func (s *Service) Stats() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := map[string]any{
		"samples_taken": s.samplesTaken,
		"error_count":   s.errorCount,
	}
	if !s.lastRun.IsZero() {
		stats["last_collection"] = s.lastRun.UTC().Format(time.RFC3339)
	}
	if s.lastError != "" {
		stats["last_error"] = s.lastError
	}
	if !s.startedAt.IsZero() {
		stats["started_at"] = s.startedAt.UTC().Format(time.RFC3339)
	}
	return stats
}

// LastCollection returns the last successful collection time (zero when
// none, or in realtime-only mode).
func (s *Service) LastCollection() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRun
}

// retentionTick is how often the collector loop runs the retention cleanup
// (the samples age in days; an hourly sweep is plenty).
const retentionTick = time.Hour

func (s *Service) loop() {
	defer close(s.done)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	cleanup := time.NewTicker(retentionTick)
	defer cleanup.Stop()

	// An immediate first collection so history exists right after enabling
	// storage, then the interval schedule. The retention cleanup runs once
	// at start too (the CleanupService convention).
	s.CollectOnce(context.Background())
	s.CleanupOld(context.Background())
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.CollectOnce(context.Background())
		case <-cleanup.C:
			s.CleanupOld(context.Background())
		}
	}
}

// CollectOnce takes one sample of every family and stores it — the collector
// tick, also invoked directly by POST /monitoring/collect. Returns the
// per-family outcomes.
func (s *Service) CollectOnce(ctx context.Context) map[string]string {
	results := map[string]string{}
	failed := ""

	if cpu, err := s.sampler.SampleCPU(ctx); err != nil {
		results["cpu"] = "failed: " + err.Error()
		failed = err.Error()
	} else if s.store != nil {
		if ierr := s.store.InsertCPU(ctx, cpu); ierr != nil {
			results["cpu"] = "store failed: " + ierr.Error()
			failed = ierr.Error()
		} else {
			results["cpu"] = "collected"
		}
	} else {
		results["cpu"] = "sampled"
	}

	if memory, err := s.sampler.SampleMemory(ctx); err != nil {
		results["memory"] = "failed: " + err.Error()
		failed = err.Error()
	} else if s.store != nil {
		if ierr := s.store.InsertMemory(ctx, memory); ierr != nil {
			results["memory"] = "store failed: " + ierr.Error()
			failed = ierr.Error()
		} else {
			results["memory"] = "collected"
		}
	} else {
		results["memory"] = "sampled"
	}

	if network, err := s.sampler.SampleNetwork(ctx); err != nil {
		results["network"] = "failed: " + err.Error()
		failed = err.Error()
	} else if s.store != nil {
		if ierr := s.store.InsertNetwork(ctx, network); ierr != nil {
			results["network"] = "store failed: " + ierr.Error()
			failed = ierr.Error()
		} else {
			results["network"] = "collected"
		}
	} else {
		results["network"] = "sampled"
	}

	s.mu.Lock()
	s.samplesTaken++
	s.lastRun = time.Now()
	if failed != "" {
		s.errorCount++
		s.lastError = failed
	}
	s.mu.Unlock()

	if failed != "" {
		monlog().Warn("monitoring collection had failures", "results", results)
	}
	return results
}

// CleanupOld deletes stored samples past the retention window — called from
// the periodic cleanup alongside task retention. No-op in realtime-only mode.
func (s *Service) CleanupOld(ctx context.Context) {
	if s.store == nil {
		return
	}
	deleted, err := s.store.DeleteBefore(ctx, time.Now().Add(-s.retain))
	if err != nil {
		monlog().Error("monitoring retention cleanup failed", "error", err)
		return
	}
	if deleted > 0 {
		monlog().Info("monitoring retention cleanup", "deleted_count", deleted)
	}
}
