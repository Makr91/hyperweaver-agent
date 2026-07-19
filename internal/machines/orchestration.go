package machines

import (
	"context"
	"sort"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine orchestration — the base's ZoneOrchestration family: machines carry
// settings.boot_priority (1-100, default 95 — the base's zonecfg attr in this
// agent's spec vocabulary, per Mark's ruling 2026-07-07), grouped by tens.
// Startup boots autostart machines highest-priority first; shutdown stops
// lowest-first (development → applications → infrastructure).

// DefaultPriority is the base's infrastructure default.
const DefaultPriority = 95

// ExtractPriority reads a machine's boot priority from its spec
// (settings.boot_priority; out-of-range and absent values default to 95 —
// extractZonePriority verbatim).
func ExtractPriority(spec *Spec) int {
	if spec == nil || spec.Settings == nil {
		return DefaultPriority
	}
	priority := int(DocInt(spec.Settings["boot_priority"], DefaultPriority))
	if priority < 1 || priority > 100 {
		return DefaultPriority
	}
	return priority
}

// PriorityEntry is one machine in an orchestration plan.
type PriorityEntry struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	State    string `json:"state"`
}

// PriorityGroup is one priority range's machines (groups of ten — the base's
// groupZonesByPriority).
type PriorityGroup struct {
	PriorityRange int             `json:"priority_range"`
	Machines      []PriorityEntry `json:"machines"`
}

// prioritized loads every spec-carrying machine with its priority.
func prioritized(ctx context.Context, store *Store) ([]PriorityEntry, error) {
	list, err := store.List(ctx, &ListFilter{})
	if err != nil {
		return nil, err
	}
	entries := []PriorityEntry{}
	for _, machine := range list {
		spec, perr := ParseSpec(machine)
		if perr != nil {
			// Discovered VMs have no spec — they ride the default priority.
			spec = nil
		}
		entries = append(entries, PriorityEntry{
			Name:     machine.Name,
			Priority: ExtractPriority(spec),
			State:    machine.Status,
		})
	}
	return entries, nil
}

// Prioritized lists every machine with its priority (GET /machines/priorities).
func Prioritized(ctx context.Context, store *Store) ([]PriorityEntry, error) {
	return prioritized(ctx, store)
}

// GroupByPriority buckets entries into ranges of ten, ascending (shutdown
// order — lowest stops first); reverse for startup.
func GroupByPriority(entries []PriorityEntry) []PriorityGroup {
	buckets := map[int][]PriorityEntry{}
	for _, entry := range entries {
		bucket := ((entry.Priority-1)/10)*10 + 10
		buckets[bucket] = append(buckets[bucket], entry)
	}
	ranges := make([]int, 0, len(buckets))
	for r := range buckets {
		ranges = append(ranges, r)
	}
	sort.Ints(ranges)
	groups := make([]PriorityGroup, 0, len(ranges))
	for _, r := range ranges {
		machines := buckets[r]
		sort.Slice(machines, func(i, j int) bool {
			return machines[i].Priority < machines[j].Priority
		})
		groups = append(groups, PriorityGroup{PriorityRange: r, Machines: machines})
	}
	return groups
}

// StartupOrchestration queues start tasks for autostart machines in priority
// order, highest first (the base's startZoneOrchestration: plain start tasks,
// created_by orchestration_startup; the queue's ordering keys preserve the
// creation order). Autostart = the spec's vbox.autostart.enabled;
// machines already running (live-checked) are skipped.
func StartupOrchestration(ctx context.Context, store *Store, queue *tasks.Queue) {
	list, err := store.List(ctx, &ListFilter{})
	if err != nil {
		mlog().Error("orchestration startup: list machines", "error", err)
		return
	}

	running := map[string]bool{}
	if exe := VBoxManagePath(ctx); exe != "" {
		if names, lerr := vbox.ListRunningVMs(ctx, exe); lerr == nil {
			for _, name := range names {
				running[name] = true
			}
		}
	}

	type candidate struct {
		name     string
		priority int
	}
	candidates := []candidate{}
	for _, machine := range list {
		spec, perr := ParseSpec(machine)
		if perr != nil {
			continue
		}
		if onOff(mapOr(spec.Vbox["autostart"])["enabled"]) != "on" {
			continue
		}
		if running[machine.Name] || (machine.UUID != nil && running[*machine.UUID]) ||
			machine.Status == StatusRunning {
			continue
		}
		candidates = append(candidates, candidate{name: machine.Name, priority: ExtractPriority(spec)})
	}
	if len(candidates) == 0 {
		mlog().Info("orchestration enabled but no autostart machines to boot")
		return
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].priority > candidates[j].priority
	})

	queued := 0
	for _, c := range candidates {
		if _, cerr := queue.Store().Create(ctx, &tasks.NewTask{
			MachineName: c.name,
			Operation:   OpStart,
			Priority:    tasks.PriorityHigh,
			CreatedBy:   "orchestration_startup",
		}); cerr != nil {
			mlog().Error("orchestration startup: queue start", "machine", c.name, "error", cerr)
			continue
		}
		queued++
	}
	mlog().Info("orchestration startup tasks created", "machines_queued", queued)
}
