package machines

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/logging"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// GuestPropertyIPName matches the Guest Additions' live per-adapter IPv4
// property keys — shared by the sweep's fallback and the server's RDP-target
// ladder (one definition, never two).
var GuestPropertyIPName = regexp.MustCompile(`^/VirtualBox/GuestInfo/Net/\d+/V4/IP$`)

// UsableGuestIP filters one reported guest address: the provisioning NAT's
// 10.0.2.x is host-unreachable by construction; loopback and unassigned
// values are noise.
func UsableGuestIP(ip string) bool {
	return ip != "" && ip != "0.0.0.0" &&
		!strings.HasPrefix(ip, "10.0.2.") && !strings.HasPrefix(ip, "127.")
}

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
	// machinesDir + guestAgent drive the sweep's guest-info probe: every
	// RUNNING machine's QGA channel is asked for its live IPs and the answer
	// is STORED on the row (configuration.guest_info) — the machine list the
	// UI already polls carries the direct-connect gate, so no per-machine
	// query storms (Mark's design ruling 2026-07-11).
	machinesDir string
	guestAgent  bool

	mu      sync.Mutex
	stopCh  chan struct{}
	done    chan struct{}
	running bool
}

// startupDiscoveryDelay mirrors the Node agent's 5-second setTimeout before
// the initial discovery task.
const startupDiscoveryDelay = 5 * time.Second

// NewReconciler builds the reconciler over the machine store; discover tasks
// are created in taskStore. machinesDir anchors QGA pipe derivation for rows
// without a working directory; guestAgent gates the sweep's guest-info probe.
func NewReconciler(store *Store, taskStore *tasks.Store, autoDiscovery bool, interval time.Duration,
	machinesDir string, guestAgent bool,
) *Reconciler {
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
		machinesDir:   machinesDir,
		guestAgent:    guestAgent,
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

// UTMCtlPath returns the validated utmctl path from the prerequisite
// detector, or "" when UTM is not installed.
func UTMCtlPath(ctx context.Context) string {
	return toolPath(ctx, "utm")
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

	discovered := 0
	updated := 0
	var seen []string
	if exe == "" {
		// No VirtualBox is not no sweep — a Mac running only UTM still
		// discovers and refreshes its utm machines. Only the VBox sweep is
		// skipped, and its rows get the same guard as an unobserved UTM:
		// every virtualbox row (and every "" row from before the hypervisor
		// column) joins seen, because a hypervisor never observed must never
		// orphan its rows.
		narrate("stderr", "VirtualBox not installed — VirtualBox sweep skipped, its registry rows left untouched")
		mlog().Debug("machine reconciliation: VirtualBox sweep skipped, not installed")
		seen = append(seen, r.hypervisorRowNames(sweepCtx, narrate, HypervisorVirtualBox, "")...)
	} else {
		registered, err := vbox.ListRegistered(sweepCtx, exe, "vms")
		if err != nil {
			// VirtualBox is PRESENT but its probe broke — the conservative
			// path: no observations, no marking, the next sweep retries.
			narrate("stderr", "VBoxManage list vms failed: "+err.Error())
			mlog().Warn("machine reconciliation: list vms failed", "error", err)
			return
		}
		narrate("stdout", "VirtualBox reports "+strconv.Itoa(len(registered))+" registered machine(s)")

		seen = make([]string, 0, len(registered))
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
				Hypervisor:    HypervisorVirtualBox,
				UUID:          reg.UUID,
				Configuration: configuration,
			}
			existing, gerr := r.store.Get(sweepCtx, reg.Name)
			if gerr == nil && existing.Backing == BackingVagrant && existing.Home != nil {
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

			// The guest-info probe: running machines get their live IPs observed
			// (QGA channel first, Guest Additions properties second) and stored on
			// the row; anything else loses the section.
			r.refreshGuestInfo(sweepCtx, exe, reg.UUID, reg.Name, existing, observation.Status, narrate)
		}
	}

	utmNames, utmDiscovered, utmUpdated, utmSwept := r.sweepUTM(sweepCtx, narrate)
	if utmSwept {
		seen = append(seen, utmNames...)
		discovered += utmDiscovered
		updated += utmUpdated
	} else {
		// A hypervisor that was never observed must never orphan its rows —
		// every existing utm machine joins seen so MarkMissing/
		// DeleteOrphanedMissing leave them alone (the VBox
		// no-observations-beats-mass-orphaning principle, per hypervisor).
		seen = append(seen, r.hypervisorRowNames(sweepCtx, narrate, HypervisorUTM)...)
	}

	// Hard-delete rows orphaned on a PREVIOUS sweep and still missing (the
	// base's reconciliation delete — Mark's ruling 2026-07-07: an externally
	// deleted VM's entry goes away; the one-sweep grace covers transient
	// unregisters). Their leftover pending tasks are cancelled. Working
	// directories stay on disk — table data only, never user files.
	deleted, err := r.store.DeleteOrphanedMissing(sweepCtx, seen)
	if err != nil {
		narrate("stderr", "orphan removal failed: "+err.Error())
		mlog().Error("machine reconciliation: delete orphaned failed", "error", err)
	}
	for _, name := range deleted {
		narrate("stderr", name+": VM gone from VirtualBox since the previous sweep — registry entry removed")
		mlog().Warn("orphaned machine removed from the registry", "machine", name)
		r.cancelPendingTasks(sweepCtx, name, narrate)
	}

	orphaned, err := r.store.MarkMissing(sweepCtx, seen)
	if err != nil {
		narrate("stderr", "orphan check failed: "+err.Error())
		mlog().Error("machine reconciliation: mark missing failed", "error", err)
	} else if orphaned > 0 {
		narrate("stderr", strconv.FormatInt(orphaned, 10)+" registry machine(s) no longer present in VirtualBox — marked orphaned (removed next sweep if still missing)")
		mlog().Warn("machines no longer present in VirtualBox marked orphaned", "count", orphaned)
	}

	// The Node agent's discover completion line.
	narrate("stdout", "Discovery completed: "+strconv.Itoa(discovered)+" new machines discovered, "+
		strconv.Itoa(updated)+" updated, "+strconv.FormatInt(orphaned, 10)+" machines orphaned, "+
		strconv.Itoa(len(deleted))+" removed")
}

// sweepUTM is the discovery sweep's second hypervisor: on darwin with utmctl
// present, UTM's machine list lands in the registry exactly like
// VirtualBox's — no Configuration document (UTM has no machinereadable map
// yet; nil is legal); running rows get the utm guest-info probe (utmctl
// ip-address). ok=false means the sweep never observed UTM (absent or
// failed) so RunOnce guards existing utm rows from orphaning.
func (r *Reconciler) sweepUTM(ctx context.Context, narrate func(stream, line string)) (names []string, discovered, updated int, ok bool) {
	utmctlPath := UTMCtlPath(ctx)
	if runtime.GOOS != "darwin" || utmctlPath == "" {
		return nil, 0, 0, false
	}
	registered, err := utm.List(ctx)
	if err != nil {
		narrate("stderr", "UTM list failed: "+err.Error())
		mlog().Warn("machine reconciliation: UTM list failed", "error", err)
		return nil, 0, 0, false
	}
	narrate("stdout", "UTM reports "+strconv.Itoa(len(registered))+" registered machine(s)")

	for _, reg := range registered {
		names = append(names, reg.Name)
		observation := Discovered{
			Name:   reg.Name,
			Host:   r.hostname,
			Status: utm.MapUTMState(reg.Status),
			// BackingVBox records "exists only in the hypervisor" provenance
			// (the const's meaning, not its name); agent-created rows keep
			// their vagrant backing below, exactly like VirtualBox ones.
			Backing:    BackingVBox,
			Hypervisor: HypervisorUTM,
			UUID:       reg.UUID,
		}
		existing, gerr := r.store.Get(ctx, reg.Name)
		if gerr == nil && existing.Backing == BackingVagrant && existing.Home != nil {
			observation.Backing = BackingVagrant
			observation.Home = existing.Home
		}
		narrate("stdout", reg.Name+": "+reg.Status+" → "+observation.Status+
			" (backing "+observation.Backing+")")
		created, uerr := r.store.UpsertDiscovered(ctx, &observation)
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

		r.refreshGuestInfoUTM(ctx, utmctlPath, reg.UUID, reg.Name, observation.Status, narrate)
	}
	return names, discovered, updated, true
}

// hypervisorRowNames lists the registry's machine names whose Hypervisor is
// one of the given values — the orphan guard's input when a sweep never
// observed that hypervisor. VirtualBox's guard passes "" alongside
// HypervisorVirtualBox: rows written before the hypervisor column carry the
// empty default and are VirtualBox's.
func (r *Reconciler) hypervisorRowNames(ctx context.Context, narrate func(stream, line string),
	hypervisors ...string,
) []string {
	rows, err := r.store.List(ctx, &ListFilter{})
	if err != nil {
		narrate("stderr", "loading rows for the orphan guard failed: "+err.Error())
		mlog().Error("machine reconciliation: list rows for the orphan guard failed", "error", err)
		return nil
	}
	names := []string{}
	for _, m := range rows {
		for _, h := range hypervisors {
			if m.Hypervisor == h {
				names = append(names, m.Name)
				break
			}
		}
	}
	return names
}

// refreshGuestInfo records one machine's live-IP observation on its row —
// configuration.guest_info {ips[], source, agent_responding, checked_at}.
// A RUNNING machine's QGA channel is probed first (guest_agent.enabled; 3s —
// qemu-ga answers in milliseconds, the timeout only bites channels nothing
// listens on); when it yields nothing, the Guest Additions' live IP
// properties are the fallback — the SAME two live sources the RDP/SSH target
// ladders dial, and NEVER the provisioning-plan control IP (Mark's ruling
// 2026-07-11: a plan address nothing answers must not present as live).
// Non-running machines lose the section — honest absence ungates the UI's
// direct-connect buttons. existing may be nil (first sight): the pipe then
// derives from the machines root, the same fallback the on-demand handlers
// use, so both sides always address the same channel.
func (r *Reconciler) refreshGuestInfo(ctx context.Context, vboxExe, target, name string,
	existing *Machine, status string, narrate func(stream, line string),
) {
	if status != StatusRunning {
		if err := r.store.SetGuestInfo(ctx, name, nil); err != nil && !errors.Is(err, ErrNotFound) {
			mlog().Warn("clear guest info failed", "machine", name, "error", err)
		}
		return
	}

	ips := []string{}
	source := ""
	responding := false
	if r.guestAgent {
		workdir := ""
		if existing != nil && existing.Home != nil {
			workdir = *existing.Home
		}
		if workdir == "" {
			workdir = filepath.Join(r.machinesDir, provisioner.MachineDirName(name))
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		agentIPs, err := qga.GuestIPv4s(probeCtx, qga.PipePath(workdir, name))
		cancel()
		responding = err == nil
		if len(agentIPs) > 0 {
			ips = agentIPs
			source = "guest-agent"
		}
	}
	if len(ips) == 0 {
		if entries, err := vbox.EnumerateGuestProperties(ctx, vboxExe, target); err == nil {
			for _, entry := range entries {
				if GuestPropertyIPName.MatchString(entry.Name) && UsableGuestIP(entry.Value) {
					ips = append(ips, entry.Value)
				}
			}
			if len(ips) > 0 {
				source = "additions"
			}
		}
	}

	switch {
	case len(ips) > 0:
		narrate("stdout", name+": guest IPs ("+source+"): "+strings.Join(ips, ", "))
	case responding:
		narrate("stdout", name+": guest agent responding, no host-reachable IP yet")
	default:
		narrate("stdout", name+": no live guest IP source (guest agent silent, no Additions)")
	}
	if serr := r.store.SetGuestInfo(ctx, name, map[string]any{
		"ips":              ips,
		"source":           source,
		"agent_responding": responding,
		"checked_at":       time.Now().UTC().Format(time.RFC3339),
	}); serr != nil {
		narrate("stderr", name+": storing guest info failed ("+serr.Error()+")")
		mlog().Warn("store guest info failed", "machine", name, "error", serr)
	}
}

// refreshGuestInfoUTM is refreshGuestInfo's utm twin: the one live source is
// utmctl ip-address (qemu-guest-agent — no UART, no Additions fallback);
// non-running machines lose the section exactly like VBox rows.
func (r *Reconciler) refreshGuestInfoUTM(ctx context.Context, utmctlPath, target, name, status string,
	narrate func(stream, line string),
) {
	if status != StatusRunning {
		if err := r.store.SetGuestInfo(ctx, name, nil); err != nil && !errors.Is(err, ErrNotFound) {
			mlog().Warn("clear guest info failed", "machine", name, "error", err)
		}
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	agentIPs, err := utm.GuestIPs(probeCtx, utmctlPath, target)
	cancel()
	responding := err == nil
	ips := []string{}
	for _, ip := range agentIPs {
		if UsableGuestIP(ip) {
			ips = append(ips, ip)
		}
	}
	source := ""
	if len(ips) > 0 {
		source = "guest-agent"
	}

	switch {
	case len(ips) > 0:
		narrate("stdout", name+": guest IPs ("+source+"): "+strings.Join(ips, ", "))
	case responding:
		narrate("stdout", name+": guest agent responding, no host-reachable IP yet")
	default:
		narrate("stdout", name+": no live guest IP source (qemu-guest-agent silent)")
	}
	if serr := r.store.SetGuestInfo(ctx, name, map[string]any{
		"ips":              ips,
		"source":           source,
		"agent_responding": responding,
		"checked_at":       time.Now().UTC().Format(time.RFC3339),
	}); serr != nil {
		narrate("stderr", name+": storing guest info failed ("+serr.Error()+")")
		mlog().Warn("store guest info failed", "machine", name, "error", serr)
	}
}

// cancelPendingTasks cancels a deleted machine's leftover pending tasks —
// they target something that no longer exists.
func (r *Reconciler) cancelPendingTasks(ctx context.Context, machineName string,
	narrate func(stream, line string),
) {
	filter := tasks.ListFilter{
		MachineName: machineName,
		Status:      tasks.StatusPending,
		Limit:       100,
	}
	pending, err := r.taskStore.List(ctx, &filter)
	if err != nil {
		narrate("stderr", machineName+": listing leftover pending tasks failed: "+err.Error())
		return
	}
	for _, t := range pending {
		if _, cerr := r.taskStore.CancelPending(ctx, t.ID); cerr != nil {
			narrate("stderr", machineName+": cancel leftover task "+t.ID+" failed: "+cerr.Error())
		} else {
			narrate("stdout", machineName+": cancelled leftover pending task "+t.ID+" ("+t.Operation+")")
		}
	}
}
