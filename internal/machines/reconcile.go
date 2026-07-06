package machines

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// mlog is this package's category logger (the Node agent's per-category
// winston loggers: logging.categories.machines overrides its level).
func mlog() *slog.Logger {
	return logging.Category("machines")
}

// Reconciler keeps the registry truthful: the periodic sweep (SHI's 60-second
// poll — this IS external-shutdown detection) lists VirtualBox's machines,
// refreshes every row's live state, imports machines built outside the agent,
// and flags registry rows whose VM disappeared. VirtualBox is the ONE
// authority (SHI's getRealStatus rule) — the agent never executes vagrant
// (Mark's provisioning-engine ruling); rows that carry vagrant provenance
// from before the cut keep it, read from the store only.
//
// The sweep runs THROUGH the task queue, exactly like the Node agent's
// TaskProcessor: an unconditional startup `discover` task 5 seconds after
// boot (created_by system_startup), and — when auto-discovery is enabled —
// one visible BACKGROUND `discover` row per discovery interval (created_by
// system_periodic), machine_name "system". The Tasks view shows exactly what
// the agent is doing and when — never a hidden background loop.
type Reconciler struct {
	store         *Store
	taskStore     *tasks.Store
	autoDiscovery bool
	interval      time.Duration
	hostname      string

	mu      sync.Mutex
	stopCh  chan struct{}
	done    chan struct{}
	running bool
}

// startupDiscoveryDelay mirrors the Node agent's 5-second setTimeout before
// the initial discovery task.
const startupDiscoveryDelay = 5 * time.Second

// NewReconciler builds the reconciler over the machine store; discover tasks
// are created in taskStore.
func NewReconciler(store *Store, taskStore *tasks.Store, autoDiscovery bool, interval time.Duration) *Reconciler {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return &Reconciler{
		store:         store,
		taskStore:     taskStore,
		autoDiscovery: autoDiscovery,
		interval:      interval,
		hostname:      hostname,
	}
}

// queueDiscover creates one visible discover task (the Node agent's
// discovery rows).
func (r *Reconciler) queueDiscover(ctx context.Context, createdBy string) {
	if _, err := r.taskStore.Create(ctx, &tasks.NewTask{
		MachineName: "system",
		Operation:   OpDiscover,
		Priority:    tasks.PriorityBackground,
		CreatedBy:   createdBy,
	}); err != nil {
		mlog().Error("queue discover task", "error", err)
	}
}

// Start schedules the startup discovery task (always) and the periodic
// discovery loop (when auto-discovery is enabled) — the Node agent's
// startTaskProcessor scheduling, verbatim.
func (r *Reconciler) Start() {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.stopCh = make(chan struct{})
	r.done = make(chan struct{})
	r.mu.Unlock()

	if r.autoDiscovery {
		mlog().Info("periodic machine discovery started", "interval", r.interval)
	} else {
		mlog().Info("periodic machine discovery disabled (machines.auto_discovery=false); startup discovery still runs")
	}

	go func() {
		defer close(r.done)

		select {
		case <-r.stopCh:
			return
		case <-time.After(startupDiscoveryDelay):
			r.queueDiscover(context.Background(), "system_startup")
		}

		if !r.autoDiscovery {
			<-r.stopCh
			return
		}
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				r.queueDiscover(context.Background(), "system_periodic")
			}
		}
	}()
}

// Stop halts periodic discovery.
func (r *Reconciler) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	close(r.stopCh)
	r.mu.Unlock()
	<-r.done
	mlog().Info("periodic machine discovery stopped")
}

// VBoxManagePath returns the validated VBoxManage path from the prerequisite
// detector, or "" when VirtualBox is not installed.
func VBoxManagePath(ctx context.Context) string {
	return toolPath(ctx, "virtualbox")
}

func toolPath(ctx context.Context, name string) string {
	for _, tool := range prereqs.Detect(ctx) {
		if tool.Name == name && tool.Installed {
			return tool.Path
		}
	}
	return ""
}

// RunOnce performs one reconciliation sweep, narrating into the discover
// task's output (out may be nil for internal calls).
func (r *Reconciler) RunOnce(ctx context.Context, out *tasks.OutputWriter) {
	narrate := func(stream, line string) {
		if out != nil {
			out.Write(stream, line+"\n")
		}
	}

	sweepCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	exe := VBoxManagePath(sweepCtx)
	if exe == "" {
		// No VirtualBox, no observations — leaving the registry as-is beats
		// mass-orphaning machines over a broken installation.
		narrate("stderr", "VirtualBox not installed — sweep skipped, registry left untouched")
		mlog().Debug("machine reconciliation skipped: VirtualBox not installed")
		return
	}

	registered, err := vbox.ListRegistered(sweepCtx, exe, "vms")
	if err != nil {
		narrate("stderr", "VBoxManage list vms failed: "+err.Error())
		mlog().Warn("machine reconciliation: list vms failed", "error", err)
		return
	}
	narrate("stdout", "VirtualBox reports "+strconv.Itoa(len(registered))+" registered machine(s)")

	discovered := 0
	updated := 0
	seen := make([]string, 0, len(registered))
	for _, reg := range registered {
		info, ierr := vbox.ShowVMInfo(sweepCtx, exe, reg.UUID)
		if ierr != nil {
			// Deleted between list and inspect — the next sweep settles it.
			narrate("stderr", reg.Name+": showvminfo failed ("+ierr.Error()+")")
			mlog().Debug("machine reconciliation: showvminfo failed",
				"machine", reg.Name, "error", ierr)
			continue
		}
		seen = append(seen, reg.Name)

		configuration, merr := json.Marshal(info.Raw)
		if merr != nil {
			mlog().Warn("machine reconciliation: serialize configuration",
				"machine", reg.Name, "error", merr)
			configuration = nil
		}

		observation := Discovered{
			Name:          reg.Name,
			Host:          r.hostname,
			Status:        MapVBoxState(info.State),
			Backing:       BackingVBox,
			UUID:          reg.UUID,
			Configuration: configuration,
		}
		if existing, gerr := r.store.Get(sweepCtx, reg.Name); gerr == nil &&
			existing.Backing == BackingVagrant && existing.Home != nil {
			// A row that carries vagrant provenance (recorded before the
			// vagrant cut, or by an agent-created machine's home) keeps its
			// backing and home — read from the store, never from vagrant.
			observation.Backing = BackingVagrant
			observation.Home = existing.Home
		}

		narrate("stdout", reg.Name+": "+info.State+" → "+observation.Status+
			" (backing "+observation.Backing+")")
		created, uerr := r.store.UpsertDiscovered(sweepCtx, &observation)
		if uerr != nil {
			narrate("stderr", reg.Name+": registry update failed ("+uerr.Error()+")")
			mlog().Error("machine reconciliation: upsert failed",
				"machine", reg.Name, "error", uerr)
			continue
		}
		if created {
			discovered++
			narrate("stdout", reg.Name+": NEW — imported into the registry")
		} else {
			updated++
		}
	}

	orphaned, err := r.store.MarkMissing(sweepCtx, seen)
	if err != nil {
		narrate("stderr", "orphan check failed: "+err.Error())
		mlog().Error("machine reconciliation: mark missing failed", "error", err)
	} else if orphaned > 0 {
		narrate("stderr", strconv.FormatInt(orphaned, 10)+" registry machine(s) no longer present in VirtualBox — marked orphaned")
		mlog().Warn("machines no longer present in VirtualBox marked orphaned", "count", orphaned)
	}

	// The Node agent's discover completion line.
	narrate("stdout", "Discovery completed: "+strconv.Itoa(discovered)+" new machines discovered, "+
		strconv.Itoa(updated)+" updated, "+strconv.FormatInt(orphaned, 10)+" machines orphaned")
}
