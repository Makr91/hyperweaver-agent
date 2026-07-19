package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine lifecycle operations (task queue vocabulary). Lifecycle is native
// VBoxManage for every machine (the zoneweaver model — the agent drives the
// hypervisor and the guest itself; vagrant/Hosts.rb are never executed). The
// machine_create_*/machine_* provisioning operations are the orchestration
// children of the create and provision chains.
const (
	OpStart    = "start"
	OpStop     = "stop"
	OpRestart  = "restart" // never dispatched: a restart is a stop→start chain
	OpSuspend  = "suspend"
	OpReset    = "reset"  // controlvm reset — the hard reboot VirtualBox offers beyond the stop→start chain
	OpPause    = "pause"  // controlvm pause
	OpResume   = "resume" // controlvm resume
	OpDelete   = "delete"
	OpDiscover = "discover"
	OpPrepare  = "machine_prepare"
)

// stopMetadata is the stop/delete task metadata document.
type stopMetadata struct {
	Force bool `json:"force"`
}

// deleteMetadata is the delete task's metadata document. CleanupDisks is the
// base's cleanup_datasets translated: false unregisters the VM but leaves
// every medium file (and the working directory holding them) on disk.
type deleteMetadata struct {
	CleanupDisks bool `json:"cleanup_disks"`
}

// RegisterExecutors wires the machine operations into the task queue:
// lifecycle, the create-orchestration children, the provision-pipeline
// children, and the template download.
func RegisterExecutors(queue *tasks.Queue, store *Store, reconciler *Reconciler, shutdownTimeout time.Duration, env *ProvisionEnv) {
	e := &executors{
		queue:           queue,
		store:           store,
		reconciler:      reconciler,
		shutdownTimeout: shutdownTimeout,
		env:             env,
	}
	queue.Register(OpStart, tasks.Executor{Run: e.start, OnCancel: e.cancelStart})
	queue.Register(OpStop, tasks.Executor{Run: e.stop})
	queue.Register(OpSuspend, tasks.Executor{Run: e.suspend})
	queue.Register(OpReset, tasks.Executor{Run: e.controlAction(OpReset, "reset")})
	queue.Register(OpPause, tasks.Executor{Run: e.controlAction(OpPause, "pause")})
	queue.Register(OpResume, tasks.Executor{Run: e.controlAction(OpResume, "resume")})
	queue.Register(OpDelete, tasks.Executor{Run: e.deleteMachine})
	queue.Register(OpDiscover, tasks.Executor{Run: e.discover})
	queue.Register(OpImport, tasks.Executor{Run: e.importAppliance})
	queue.Register(OpMove, tasks.Executor{Run: e.moveMachine})
	queue.Register(OpUnattended, tasks.Executor{Run: e.unattendedInstall})

	// Snapshot family + current-state clone (VBoxManage snapshot/clonevm —
	// yardstick 2: the whole hypervisor surface, policy-free).
	queue.Register(OpSnapshotTake, tasks.Executor{Run: e.snapshotTake})
	queue.Register(OpSnapshotRestore, tasks.Executor{Run: e.snapshotRestore})
	queue.Register(OpSnapshotDelete, tasks.Executor{Run: e.snapshotDelete})
	queue.Register(OpSnapshotModify, tasks.Executor{Run: e.snapshotModify})
	queue.Register(OpCloneCurrent, tasks.Executor{Run: e.cloneCurrent})
	queue.Register(OpTemplateDelete, tasks.Executor{Run: e.templateDelete})
	queue.Register(OpTemplateExport, tasks.Executor{Run: e.templateExport})
	queue.Register(OpTemplatePublish, tasks.Executor{Run: e.templatePublish})
	queue.Register(OpTemplateMove, tasks.Executor{Run: e.templateMove})
	// machine_modify — the base's zone_modify (TASK_OBJECT_OPERATIONS +
	// zone_lifecycle category). Its serialization guard here is the queue's
	// one-running-task-per-machine rule, so it stays category-unmapped.
	queue.Register(OpModify, tasks.Executor{Run: e.modifyMachine})

	// Create-orchestration children (storage/config carry post-kill cleanup:
	// a cancellation mid-clone or mid-configure must not leave debris).
	queue.Register(OpPrepare, tasks.Executor{Run: e.prepareDocument})
	queue.Register(OpCreateStorage, tasks.Executor{Run: e.createStorage, OnCancel: e.cancelCreateStorage})
	queue.Register(OpCreateConfig, tasks.Executor{Run: e.createConfig, OnCancel: e.cancelCreateConfig})
	queue.Register(OpCreateFinalize, tasks.Executor{Run: e.createFinalize})
	queue.Register(OpTemplateDownload, tasks.Executor{Run: e.templateDownload})

	// Provisioning-network backbone (the base's setup/teardown operations,
	// category-locked like its network_provisioning family).
	queue.Register(OpNetworkSetup, tasks.Executor{Run: e.networkSetup})
	queue.Register(OpNetworkTeardown, tasks.Executor{Run: e.networkTeardown})

	// Provision-chain children — the ONE document walk (Mark's ruling
	// 2026-07-17: there are no phases): the stored provisioning: section's
	// methods and hooks chain directly under the orchestration parent in
	// document order; sync/syncback keep their sub-parents as the walk's
	// outer brackets.
	queue.Register(OpWaitSSH, tasks.Executor{Run: e.waitSSH})
	queue.Register(OpSyncParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpSyncFolder, tasks.Executor{Run: e.syncFolder})
	queue.Register(OpShellScript, tasks.Executor{Run: e.runShellScript})
	// OpProvisionParent survives ONLY as the /run-provisioners anchor.
	queue.Register(OpProvisionParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpProvisionPlaybook, tasks.Executor{Run: e.provisionPlaybook})
	// local/remote is an entry's execution MECHANISM (in-guest ansible vs
	// ansible-playbook on the agent host), never a phase.
	queue.Register(OpRemotePlaybook, tasks.Executor{Run: e.runRemotePlaybook})
	queue.Register(OpDockerCompose, tasks.Executor{Run: e.dockerCompose})
	// Sequence hooks (provisioning.pre[]/post[]) — ONE operation; the entry's
	// own target picks guest or host.
	queue.Register(OpHook, tasks.Executor{Run: e.runHook})
	// Syncback (folders[].syncback — guest→host pulls, the walk's closing
	// bracket by document structure, and ad-hoc via POST
	// /machines/{name}/sync {"syncback": true}).
	queue.Register(OpSyncbackParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpSyncbackFolder, tasks.Executor{Run: e.syncbackFolder})
	// Key rotation (machine_key_rotate — key_rotate proposal, sync
	// 2026-07-17): after the syncback bracket, adopt the box's rotated
	// private key into the working copy; never the whole-walk stamp owner.
	queue.Register(OpKeyRotate, tasks.Executor{Run: e.keyRotate})
	// Transport removal (machine_transport_remove — the remove-on-completion
	// flag, converged sync 2026-07-18): between the pipeline-owned stop and
	// boot after the whole-walk stamp, remove the flagged adapters and update
	// the document to match.
	queue.Register(OpTransportRemove, tasks.Executor{Run: e.transportRemove})
}

type executors struct {
	queue           *tasks.Queue
	store           *Store
	reconciler      *Reconciler
	shutdownTimeout time.Duration
	env             *ProvisionEnv
}

// resolve loads the machine a task targets and the VBoxManage path.
func (e *executors) resolve(ctx context.Context, task *tasks.Task) (*Machine, string, error) {
	machine, err := e.store.Get(ctx, task.MachineName)
	if err != nil {
		return nil, "", fmt.Errorf("machine %s: %w", task.MachineName, err)
	}
	exe := VBoxManagePath(ctx)
	if exe == "" {
		return nil, "", errors.New("VirtualBox is not installed")
	}
	return machine, exe, nil
}

// refreshStatus records the machine's live state after an operation. The row
// is reloaded first so the freshest UUID addresses the VM.
func (e *executors) refreshStatus(name, vboxExe string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	machine, err := e.store.Get(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			mlog().Error("reload machine for refresh", "machine", name, "error", err)
		}
		return
	}
	info, err := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		// No VM behind a UUID-less row is its normal configured state, not
		// an orphan (MarkMissing's rule).
		if machine.UUID == nil {
			return
		}
		if serr := e.store.SetOrphaned(ctx, name, true); serr != nil &&
			!errors.Is(serr, ErrNotFound) {
			mlog().Error("record machine orphaned", "machine", name, "error", serr)
		}
		return
	}
	if err != nil {
		mlog().Warn("refresh machine status failed", "machine", name, "error", err)
		return
	}
	if serr := e.store.SetStatus(ctx, name, MapVBoxState(info.State)); serr != nil {
		mlog().Error("record machine status", "machine", name, "error", serr)
	}
}

// start boots a machine: `VBoxManage startvm --type headless` — one native
// path for every machine (the provision pipeline queues this same operation
// as its boot child).
func (e *executors) start(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	out.Write("stdout", "Starting "+machine.Name+" (VBoxManage startvm --type headless)\n")
	if serr := vbox.StartVM(ctx, vboxExe, machine.VBoxTarget(), false); serr != nil {
		out.Write("stderr", "Failed to start machine "+machine.Name+": "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Machine "+machine.Name+" started successfully\n")
	return nil
}

// cancelStart is the start operation's post-kill cleanup (D-F): the killed
// start leaves a half-up VM — force it off so it is not left running
// unattended.
func (e *executors) cancelStart(task *tasks.Task, out *tasks.OutputWriter) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	exe := VBoxManagePath(ctx)
	if exe == "" {
		return
	}
	target := task.MachineName
	if machine, err := e.store.Get(ctx, task.MachineName); err == nil {
		target = machine.VBoxTarget()
	}
	out.Write("stderr", "Start cancelled — forcing the machine off\n")
	if err := vbox.ControlVM(ctx, exe, target, "poweroff"); err != nil {
		// Never-booted machines have nothing to power off; that is success.
		out.Write("stderr", "Power off after cancel: "+err.Error()+"\n")
	}
	e.refreshStatus(task.MachineName, exe)
}

// stop halts a machine: ACPI power button first, hard poweroff when the
// guest ignores it or when the request forced.
func (e *executors) stop(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	var meta stopMetadata
	if task.Metadata != nil {
		if uerr := json.Unmarshal([]byte(*task.Metadata), &meta); uerr != nil {
			return fmt.Errorf("parse stop metadata: %w", uerr)
		}
	}

	target := machine.VBoxTarget()
	if !meta.Force {
		// The graceful ladder (Mark's go 2026-07-12): the guest agent's OWN
		// orderly shutdown first — the guest OS acting on itself, honored
		// regardless of session state (a locked Windows console ignores
		// ACPI's power button; qemu-ga does not) — ACPI when the channel is
		// silent, hard poweroff last. A DELIVERED guest-shutdown that still
		// times out goes straight to poweroff: the guest already ignored its
		// own OS shutdown, the ACPI button adds nothing but a second wait.
		if e.guestShutdown(ctx, machine, out) {
			if e.waitForPowerOff(ctx, vboxExe, target, out) {
				out.Write("stdout", "Machine "+machine.Name+" stopped successfully\n")
				return nil
			}
			out.Write("stderr", "Guest shutdown did not complete; forcing power off\n")
		} else if aerr := vbox.ControlVM(ctx, vboxExe, target, "acpipowerbutton"); aerr == nil {
			out.Write("stdout", "Stopping "+machine.Name+" gracefully (ACPI power button)\n")
			if e.waitForPowerOff(ctx, vboxExe, target, out) {
				out.Write("stdout", "Machine "+machine.Name+" stopped successfully\n")
				return nil
			}
			out.Write("stderr", "Graceful shutdown did not complete; forcing power off\n")
		} else {
			out.Write("stderr", "ACPI signal failed ("+aerr.Error()+"); forcing power off\n")
		}
	} else {
		out.Write("stdout", "Stopping "+machine.Name+" (forced)\n")
	}

	if perr := vbox.ControlVM(ctx, vboxExe, target, "poweroff"); perr != nil {
		out.Write("stderr", "Failed to stop machine "+machine.Name+": "+perr.Error()+"\n")
		return perr
	}
	out.Write("stdout", "Machine "+machine.Name+" stopped successfully\n")
	return nil
}

// guestShutdown asks the guest agent for an orderly powerdown — the stop
// ladder's first rung (true = delivered; silence after delivery is the
// NORMAL exit, the guest dies before replying). False on any channel
// failure — no UART, no qemu-ga, master gate off — and the ACPI rung takes
// over. 5s bound: qemu-ga answers in milliseconds; the timeout only bites
// channels nothing listens on.
func (e *executors) guestShutdown(ctx context.Context, machine *Machine, out *tasks.OutputWriter) bool {
	if !e.env.GuestAgentEnabled {
		return false
	}
	workdir := e.machineWorkdir(machine.Name)
	if machine.Home != nil && *machine.Home != "" {
		workdir = *machine.Home
	}
	pipe := qga.PipePath(workdir, machine.Name)
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := qga.Do(callCtx, pipe, "guest-shutdown", map[string]any{"mode": "powerdown"}); err != nil &&
		!errors.Is(err, qga.ErrNoReply) {
		out.Write("stdout", "Guest agent unavailable — falling back to ACPI ("+err.Error()+")\n")
		return false
	}
	out.Write("stdout", "Stopping "+machine.Name+" gracefully (guest-agent shutdown)\n")
	return true
}

// waitForPowerOff polls until a gracefully-signalled machine leaves the
// running state, bounded by machines.shutdown_timeout. False on timeout —
// the caller falls back to a hard poweroff.
func (e *executors) waitForPowerOff(ctx context.Context, vboxExe, target string, out *tasks.OutputWriter) bool {
	deadline := time.Now().Add(e.shutdownTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
		info, err := vbox.ShowVMInfo(ctx, vboxExe, target)
		if err != nil {
			return false
		}
		if MapVBoxState(info.State) != StatusRunning {
			out.Write("stdout", "Machine reports state: "+info.State+"\n")
			return true
		}
	}
	return false
}

// suspend saves a machine's state (`controlvm savestate`).
func (e *executors) suspend(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	out.Write("stdout", "Suspending "+machine.Name+" (VBoxManage savestate)\n")
	if serr := vbox.ControlVM(ctx, vboxExe, machine.VBoxTarget(), "savestate"); serr != nil {
		out.Write("stderr", "Failed to suspend machine "+machine.Name+": "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Machine "+machine.Name+" suspended successfully\n")
	return nil
}

// controlAction builds a one-verb controlvm executor (reset/pause/resume) —
// the same shape start/suspend follow, without a bespoke function per verb.
func (e *executors) controlAction(operation, action string) func(context.Context, *tasks.Task, *tasks.OutputWriter) error {
	return func(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
		machine, vboxExe, err := e.resolve(ctx, task)
		if err != nil {
			return err
		}
		defer e.refreshStatus(machine.Name, vboxExe)

		out.Write("stdout", "Running "+operation+" on "+machine.Name+" (VBoxManage controlvm "+action+")\n")
		if serr := vbox.ControlVM(ctx, vboxExe, machine.VBoxTarget(), action); serr != nil {
			out.Write("stderr", "Failed to "+operation+" machine "+machine.Name+": "+serr.Error()+"\n")
			return serr
		}
		out.Write("stdout", "Machine "+machine.Name+" "+operation+" completed\n")
		return nil
	}
}

// attachmentPattern matches machinereadable storage-attachment keys on ANY
// controller ("<controller>-<port>-<device>") — the delete safety sweep reads
// every attached medium path through it.
var attachmentPattern = regexp.MustCompile(`^(.+)-(\d+)-(\d+)$`)

// detachForeignMedia detaches every attached medium WITHOUT a provenance
// stamp before an unregister --delete can destroy it — the typed disk spec's
// stamp rule (converged, sync 2026-07-17): a stamp (the hyperweaver:source
// medium property, or the .hw-source sidecar) marks a medium the agent
// CREATED (template clone / blank VDI), and cleanup_disks destroys ONLY
// those; everything unstamped (image attaches, ISOs, pre-stamp media) is
// foreign — detached and preserved with a narrated skip, WHEREVER it lives.
// The old workdir-prefix heuristic died with this rule. One honest caveat
// narrates: cleanup_disks also removes the machine's working directory, so a
// foreign medium whose FILE lies inside it still goes with the directory.
func (e *executors) detachForeignMedia(ctx context.Context, vboxExe, target string,
	info *vbox.Info, workdir string, out *tasks.OutputWriter,
) {
	prefix := strings.ToLower(filepath.Clean(workdir)) + string(filepath.Separator)
	for key, value := range info.Raw {
		if value == "none" || value == "emptydrive" || value == "" {
			continue
		}
		match := attachmentPattern.FindStringSubmatch(key)
		if match == nil || strings.Contains(key, "ImageUUID") {
			continue
		}
		if !filepath.IsAbs(value) {
			continue
		}
		if stamp := MediumSourceStamp(ctx, vboxExe, value); stamp != "" {
			out.Write("stdout", "Medium "+value+" carries stamp "+stamp+" — ours; cleanup_disks destroys it\n")
			continue
		}
		port, perr := strconv.Atoi(match[2])
		device, derr := strconv.Atoi(match[3])
		if perr != nil || derr != nil {
			continue
		}
		note := ""
		if strings.HasPrefix(strings.ToLower(filepath.Clean(value)), prefix) {
			note = " — NOTE: its file lies inside the working directory, which cleanup_disks removes"
		}
		out.Write("stdout", "Detaching unstamped medium (foreign — preserved"+note+"): "+value+"\n")
		if uerr := vbox.StorageDetachDevice(ctx, vboxExe, target, match[1], port, device); uerr != nil {
			out.Write("stderr", "Detach of "+value+" failed — VirtualBox may refuse to delete it anyway: "+uerr.Error()+"\n")
		}
	}
}

// deleteMachine destroys a machine: power off if running, detach every
// UNSTAMPED medium (the typed-disk stamp rule, converged sync 2026-07-17 —
// only media the agent created carry the provenance stamp and get deleted;
// foreign media are never the agent's to destroy), unregister — with media
// deletion when cleanup_disks (default) — remove the working directory
// (containment-checked), the registry row, and any leftover pending tasks.
// cleanup_disks=false leaves all medium files and the working directory on
// disk (the base's keep-datasets default, available here as the explicit
// flag).
func (e *executors) deleteMachine(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}

	meta := deleteMetadata{CleanupDisks: true}
	if task.Metadata != nil {
		if uerr := json.Unmarshal([]byte(*task.Metadata), &meta); uerr != nil {
			return fmt.Errorf("parse delete metadata: %w", uerr)
		}
	}

	target := machine.VBoxTarget()
	info, ierr := vbox.ShowVMInfo(ctx, vboxExe, target)
	if ierr == nil {
		if MapVBoxState(info.State) == StatusRunning {
			out.Write("stdout", "Powering off "+machine.Name+" before unregistering\n")
			if perr := vbox.ControlVM(ctx, vboxExe, target, "poweroff"); perr != nil {
				out.Write("stderr", "Power off failed: "+perr.Error()+"\n")
			}
		}
		// Lease cleanup precedes unregister — the DHCP individual config's
		// --vm reference stops resolving the moment the VM is gone.
		e.removeDHCPLeases(ctx, vboxExe, machine, out)
		workdir := e.machineWorkdir(machine.Name)
		if machine.Home != nil && *machine.Home != "" {
			workdir = *machine.Home
		}
		if meta.CleanupDisks {
			e.detachForeignMedia(ctx, vboxExe, target, info, workdir, out)
			out.Write("stdout", "Unregistering "+machine.Name+" from VirtualBox (deleting stamped media)\n")
		} else {
			out.Write("stdout", "Unregistering "+machine.Name+" from VirtualBox (cleanup_disks=false — all medium files preserved)\n")
		}
		if uerr := vbox.UnregisterVM(ctx, vboxExe, target, meta.CleanupDisks); uerr != nil {
			return uerr
		}
	} else if !errors.Is(ierr, vbox.ErrNotFound) {
		return ierr
	}

	if meta.CleanupDisks {
		e.removeWorkdir(machine, out)
	} else {
		out.Write("stdout", "Working directory preserved (cleanup_disks=false)\n")
	}

	out.Write("stdout", "Removing "+machine.Name+" from the registry\n")
	if derr := e.store.Delete(ctx, machine.Name); derr != nil && !errors.Is(derr, ErrNotFound) {
		return derr
	}

	// Any remaining pending tasks for the machine are cancelled — they
	// target something that no longer exists.
	filter := tasks.ListFilter{
		MachineName: machine.Name,
		Status:      tasks.StatusPending,
		Limit:       100,
	}
	if pending, lerr := e.queue.Store().List(ctx, &filter); lerr != nil {
		out.Write("stderr", "Listing leftover pending tasks failed: "+lerr.Error()+"\n")
	} else {
		for _, t := range pending {
			if _, cerr := e.queue.Cancel(ctx, t.ID); cerr != nil {
				out.Write("stderr", "Cancel leftover task "+t.ID+" failed: "+cerr.Error()+"\n")
			} else {
				out.Write("stdout", "Cancelled leftover pending task "+t.ID+" ("+t.Operation+")\n")
			}
		}
	}
	return nil
}

// discover runs one reconciliation sweep as a queued task.
func (e *executors) discover(ctx context.Context, _ *tasks.Task, out *tasks.OutputWriter) error {
	out.Write("stdout", "Reconciling registry against VirtualBox\n")
	e.reconciler.RunOnce(ctx, out)
	return nil
}
