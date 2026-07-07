package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
	OpDelete   = "delete"
	OpDiscover = "discover"
	OpPrepare  = "machine_prepare"
)

// stopMetadata is the stop/delete task metadata document.
type stopMetadata struct {
	Force bool `json:"force"`
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
	queue.Register(OpDelete, tasks.Executor{Run: e.deleteMachine})
	queue.Register(OpDiscover, tasks.Executor{Run: e.discover})
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

	// Provision-pipeline children.
	queue.Register(OpWaitSSH, tasks.Executor{Run: e.waitSSH})
	queue.Register(OpSyncParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpSyncFolder, tasks.Executor{Run: e.syncFolder})
	queue.Register(OpProvisionParent, tasks.Executor{Run: e.parentAnchor})
	queue.Register(OpProvisionPlaybook, tasks.Executor{Run: e.provisionPlaybook})
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
		out.Write("stdout", "Stopping "+machine.Name+" gracefully (ACPI power button)\n")
		if aerr := vbox.ControlVM(ctx, vboxExe, target, "acpipowerbutton"); aerr == nil {
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

// waitForPowerOff polls until an ACPI-signalled machine leaves the running
// state, bounded by machines.shutdown_timeout. False on timeout — the caller
// falls back to a hard poweroff.
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

// deleteMachine destroys a machine: power off if running, unregister with
// media deletion, remove the working directory (containment-checked), the
// registry row, and any leftover pending tasks.
func (e *executors) deleteMachine(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
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
		out.Write("stdout", "Unregistering "+machine.Name+" from VirtualBox (deleting media)\n")
		if uerr := vbox.UnregisterVM(ctx, vboxExe, target, true); uerr != nil {
			return uerr
		}
	} else if !errors.Is(ierr, vbox.ErrNotFound) {
		return ierr
	}

	e.removeWorkdir(machine, out)

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
