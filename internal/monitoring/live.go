package monitoring

import (
	"context"
	"sync"
	"time"
)

// LiveSampler takes every telemetry family on a cadence while started and hands each round to its callback; nothing is stored.
type LiveSampler struct {
	sampler *Sampler

	mu        sync.Mutex
	running   bool
	interval  time.Duration
	stopCh    chan struct{}
	done      chan struct{}
	onSampled func(cpu *CPUSample, memory *MemorySample, network []NetworkSample)
}

// NewLiveSampler builds the live sampler over the shared sampler.
func NewLiveSampler(sampler *Sampler) *LiveSampler {
	return &LiveSampler{sampler: sampler}
}

// SetOnSampled attaches the function called with every round's samples.
func (l *LiveSampler) SetOnSampled(fn func(cpu *CPUSample, memory *MemorySample, network []NetworkSample)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onSampled = fn
}

// Start launches the sampling loop at interval. No-op while running.
func (l *LiveSampler) Start(interval time.Duration) {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return
	}
	l.running = true
	l.interval = interval
	l.stopCh = make(chan struct{})
	l.done = make(chan struct{})
	stopCh, done := l.stopCh, l.done
	l.mu.Unlock()

	monlog().Info("monitoring live sampling started", "interval", interval)
	go l.loop(interval, stopCh, done)
}

// Stop halts the sampling loop and waits for it. No-op when not running.
func (l *LiveSampler) Stop() {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return
	}
	l.running = false
	close(l.stopCh)
	done := l.done
	l.mu.Unlock()
	<-done
	monlog().Info("monitoring live sampling stopped")
}

// Running reports whether the sampling loop is active.
func (l *LiveSampler) Running() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// Interval answers the running loop's cadence, zero when stopped.
func (l *LiveSampler) Interval() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.running {
		return 0
	}
	return l.interval
}

func (l *LiveSampler) loop(interval time.Duration, stopCh, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	l.sampleOnce(context.Background())
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			l.sampleOnce(context.Background())
		}
	}
}

func (l *LiveSampler) sampleOnce(ctx context.Context) {
	cpu, cerr := l.sampler.SampleCPU(ctx)
	if cerr != nil {
		monlog().Warn("live cpu sample failed", "error", cerr)
	}
	memory, merr := l.sampler.SampleMemory(ctx)
	if merr != nil {
		monlog().Warn("live memory sample failed", "error", merr)
	}
	network, nerr := l.sampler.SampleNetwork(ctx)
	if nerr != nil {
		monlog().Warn("live network sample failed", "error", nerr)
	}

	l.mu.Lock()
	onSampled := l.onSampled
	l.mu.Unlock()
	if onSampled != nil {
		onSampled(cpu, memory, network)
	}
}
