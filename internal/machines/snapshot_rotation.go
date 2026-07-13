package machines

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The snapshot rotation service — zoneweaver's SnapshotRotationService
// (Snapshoter.sh's cron replaced in-agent) ported to this hypervisor's
// VBoxManage snapshot family (Mark's ruling 2026-07-12: same vocabulary on
// both agents, VBox-tuned conservative defaults). Every machine is
// snapshotted on the standing schedule under the agent-level default policy;
// a per-machine policy (configuration.snapshots, the PUT `snapshots` field)
// OVERRIDES the default — including disabling (type none). Retention types:
//
//	none     — scheduled snapshots off for that machine
//	simple   — auto-<ts> snapshots on the simple/age cadence, keep the newest N
//	age      — auto-<ts> snapshots, delete those older than max_age_days
//	rotation — Snapshoter.sh semantics: hourly (:00, hours 1-23), daily
//	           (00:00 Sun-Fri), weekly (00:00 Sat), each tier keeping its own
//	           count
//
// The work rides the task queue as visible snapshot_take rows (created_by
// snapshot_rotation, BACKGROUND priority) — never a hidden loop; per-machine
// exclusivity serializes them against lifecycle like every other operation.

// SnapshotTier is one rotation tier's keep count.
type SnapshotTier struct {
	Keep int `json:"keep"`
}

// SnapshotPolicy is one retention policy — the shared zoneweaver vocabulary
// (the config's default_policy and the per-machine configuration.snapshots
// override decode into it; unknown extra keys are ignored).
type SnapshotPolicy struct {
	Type       string                  `json:"type"`
	Quiesce    bool                    `json:"quiesce,omitempty"`
	Keep       int                     `json:"keep,omitempty"`
	MaxAgeDays int                     `json:"max_age_days,omitempty"`
	Tiers      map[string]SnapshotTier `json:"tiers,omitempty"`
}

// defaultRotationTiers are the VBox-conservative tier keeps applied when a
// rotation policy names no tiers (zoneweaver defaults 24/8/5 — here pruning
// is a physical merge, so the keeps stay low).
var defaultRotationTiers = map[string]SnapshotTier{
	"hourly": {Keep: 2},
	"daily":  {Keep: 3},
	"weekly": {Keep: 2},
}

// SnapshotRotationConfig wires the service (config snapshots.*).
type SnapshotRotationConfig struct {
	Enabled bool
	// Interval is the simple/age cadence (snapshots.interval_minutes).
	Interval      time.Duration
	DefaultPolicy SnapshotPolicy
}

// SnapshotRotation is the rotation service.
type SnapshotRotation struct {
	store     *Store
	taskStore *tasks.Store
	cfg       SnapshotRotationConfig

	mu             sync.Mutex
	running        bool
	stopCh         chan struct{}
	done           chan struct{}
	lastSimpleFire time.Time
}

// NewSnapshotRotation builds the service over the machine and task stores.
func NewSnapshotRotation(store *Store, taskStore *tasks.Store, cfg SnapshotRotationConfig) *SnapshotRotation {
	return &SnapshotRotation{store: store, taskStore: taskStore, cfg: cfg}
}

// Start launches the minute tick when snapshots.enabled.
func (r *SnapshotRotation) Start() {
	if !r.cfg.Enabled {
		return
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.stopCh = make(chan struct{})
	r.done = make(chan struct{})
	r.mu.Unlock()

	mlog().Info("snapshot rotation service started",
		"default_type", r.cfg.DefaultPolicy.Type,
		"interval", r.cfg.Interval)
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				now := time.Now()
				fireSimple := now.Sub(r.lastSimpleFire) >= r.cfg.Interval
				if fireSimple {
					r.lastSimpleFire = now
				}
				r.tick(now, fireSimple)
			}
		}
	}()
}

// Stop halts the tick loop.
func (r *SnapshotRotation) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	close(r.stopCh)
	r.mu.Unlock()
	<-r.done
	mlog().Info("snapshot rotation service stopped")
}

// dueRotationTiers answers the rotation tiers due at a given minute —
// Snapshoter.sh's cron trio verbatim: hourly at :00 of hours 1-23, daily at
// 00:00 Sun-Fri, weekly at 00:00 Saturday (the tiers never double-fire at
// midnight).
func dueRotationTiers(now time.Time) []string {
	if now.Minute() != 0 {
		return nil
	}
	if now.Hour() != 0 {
		return []string{"hourly"}
	}
	if now.Weekday() == time.Saturday {
		return []string{"weekly"}
	}
	return []string{"daily"}
}

// effectiveSnapshotPolicy resolves one machine's policy: the stored
// configuration.snapshots override (an object with a type) wins, else the
// agent default.
func (r *SnapshotRotation) effectiveSnapshotPolicy(machine *Machine) SnapshotPolicy {
	override := ParseConfiguration(machine).Section("snapshots")
	if kind, _ := override["type"].(string); kind != "" {
		return decodeInto[SnapshotPolicy](override)
	}
	return r.cfg.DefaultPolicy
}

// tick evaluates every machine once. fireSimple gates the simple/age
// policies onto the interval cadence; rotation rides the wall clock.
func (r *SnapshotRotation) tick(now time.Time, fireSimple bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tiers := dueRotationTiers(now)
	list, err := r.store.List(ctx, &ListFilter{})
	if err != nil {
		mlog().Error("snapshot rotation: list machines", "error", err)
		return
	}
	for _, machine := range list {
		// Rows with no VM behind them have nothing to snapshot: configured
		// stubs (no UUID yet) and orphans (VM gone).
		if machine.UUID == nil || *machine.UUID == "" || machine.IsOrphaned {
			continue
		}
		policy := r.effectiveSnapshotPolicy(machine)
		switch policy.Type {
		case "rotation":
			if len(tiers) == 0 {
				continue
			}
			configuredTiers := policy.Tiers
			if len(configuredTiers) == 0 {
				configuredTiers = defaultRotationTiers
			}
			for _, tier := range tiers {
				keep := configuredTiers[tier].Keep
				if keep < 1 {
					keep = defaultRotationTiers[tier].Keep
				}
				r.queueSnapshot(ctx, machine.Name, map[string]any{
					"prefix":    tier,
					"retention": keep,
					"quiesce":   policy.Quiesce,
				})
			}
		case "simple":
			if !fireSimple {
				continue
			}
			keep := policy.Keep
			if keep < 1 {
				keep = 3
			}
			r.queueSnapshot(ctx, machine.Name, map[string]any{
				"prefix":    "auto",
				"retention": keep,
				"quiesce":   policy.Quiesce,
			})
		case "age":
			if !fireSimple {
				continue
			}
			maxAge := policy.MaxAgeDays
			if maxAge < 1 {
				maxAge = 7
			}
			r.queueSnapshot(ctx, machine.Name, map[string]any{
				"prefix":       "auto",
				"retention":    0,
				"max_age_days": maxAge,
				"quiesce":      policy.Quiesce,
			})
		default:
			// none (and anything unrecognized): scheduled snapshots off.
		}
	}
}

// queueSnapshot creates one snapshot_take row, deduped against an already
// pending/running snapshot_take for the machine (zoneweaver's rule — a slow
// take must not stack a second one behind it).
func (r *SnapshotRotation) queueSnapshot(ctx context.Context, machineName string, metadata map[string]any) {
	for _, status := range []string{tasks.StatusPending, tasks.StatusRunning} {
		existing, err := r.taskStore.List(ctx, &tasks.ListFilter{
			MachineName: machineName,
			Operation:   OpSnapshotTake,
			Status:      status,
			Limit:       1,
		})
		if err != nil {
			mlog().Error("snapshot rotation: dedup check", "machine", machineName, "error", err)
			return
		}
		if len(existing) > 0 {
			return
		}
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		mlog().Error("snapshot rotation: serialize metadata", "machine", machineName, "error", err)
		return
	}
	metadataStr := string(raw)
	if _, cerr := r.taskStore.Create(ctx, &tasks.NewTask{
		MachineName: machineName,
		Operation:   OpSnapshotTake,
		Priority:    tasks.PriorityBackground,
		CreatedBy:   "snapshot_rotation",
		Metadata:    &metadataStr,
	}); cerr != nil {
		mlog().Error("snapshot rotation: queue snapshot", "machine", machineName, "error", cerr)
	}
}
