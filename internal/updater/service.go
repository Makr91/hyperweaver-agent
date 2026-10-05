package updater

import (
	"context"
	"crypto/rand"
	"log/slog"
	"math/big"
	"sync"
	"time"
)

const checkStartDelay = 30 * time.Second

// Service runs the scheduled update check: once shortly after start, then every interval plus a random jitter of up to a tenth of it.
type Service struct {
	url            string
	currentVersion string
	interval       time.Duration

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	done    chan struct{}
	onNewer func(info *Info)
}

// NewService builds the scheduled checker over the versioninfo URL, the running version and the interval between checks.
func NewService(url, currentVersion string, interval time.Duration) *Service {
	return &Service{url: url, currentVersion: currentVersion, interval: interval}
}

// SetOnNewer attaches the function called with the document when a check finds a newer release.
func (s *Service) SetOnNewer(fn func(info *Info)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onNewer = fn
}

// Start launches the check loop. No-op when no versioninfo URL is configured.
func (s *Service) Start() {
	if s.url == "" {
		slog.Info("update checking is not configured; scheduled checks disabled")
		return
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.done = make(chan struct{})
	s.mu.Unlock()

	slog.Info("scheduled update checks started", "interval", s.interval, "first_check_in", checkStartDelay)
	go s.loop()
}

// Stop halts the check loop. No-op when not running.
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
	slog.Info("scheduled update checks stopped")
}

func (s *Service) nextDelay() time.Duration {
	jitter, err := rand.Int(rand.Reader, big.NewInt(int64(s.interval/10)+1))
	if err != nil {
		return s.interval
	}
	return s.interval + time.Duration(jitter.Int64())
}

func (s *Service) loop() {
	defer close(s.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.stopCh
		cancel()
	}()

	timer := time.NewTimer(checkStartDelay)
	defer timer.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-timer.C:
			s.checkOnce(ctx)
			timer.Reset(s.nextDelay())
		}
	}
}

func (s *Service) checkOnce(ctx context.Context) {
	info, available, err := Check(ctx, s.url, s.currentVersion)
	if err != nil {
		slog.Warn("scheduled update check failed", "error", err, "url", s.url)
		return
	}
	s.mu.Lock()
	onNewer := s.onNewer
	s.mu.Unlock()
	if available && onNewer != nil {
		onNewer(info)
	}
}
