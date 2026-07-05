package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine lifecycle operations (task queue vocabulary, Node-agent parity).
const (
	OpStart    = "start"
	OpStop     = "stop"
	OpRestart  = "restart" // never dispatched: a restart is a stop→start chain
	OpSuspend  = "suspend"
	OpDelete   = "delete"
	OpDiscover = "discover"
)

// stopMetadata is the stop/delete task metadata document.
type stopMetadata struct {
	Force bool `json:"force"`
}

// RegisterExecutors wires the machine lifecycle operations into the task
// queue. Lifecycle is hypervisor commands ONLY — the Node agent's
// ZoneManager model (zoneadm boot/shutdown/halt), spoken in VBoxManage
// (Mark's ruling, 2026-07-05). Vagrant appears nowhere in lifecycle; it
// returns with the provisioning phase, where it belongs.
func RegisterExecutors(queue *tasks.Queue, store *Store, reconciler *Reconciler) {
	e := &executors{queue: queue, store: store, reconciler: reconciler}
	queue.Register(OpStart, tasks.Executor{Run: e.start, OnCancel: e.cancelStart})
	queue.Register(OpStop, tasks.Executor{Run: e.stop})
	queue.Register(OpSuspend, tasks.Executor{Run: e.suspend})
	queue.Register(OpDelete, tasks.Executor{Run: e.deleteMachine})
	queue.Register(OpDiscover, tasks.Executor{Run: e.discover})
}

type executors struct {
	queue      *tasks.Queue
	store      *Store
	reconciler *Reconciler
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

// refreshStatus records the machine's live state after an operation (SHI's
// targeted showvminfo refresh).
func (e *executors) refreshStatus(name, vboxExe string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, name)
	if errors.Is(err, vbox.ErrNotFound) {
		if serr := e.store.SetOrphaned(ctx, name, true); serr != nil &&
			!errors.Is(serr, ErrNotFound) {
			slog.Error("record machine orphaned", "machine", name, "error", serr)
		}
		return
	}
	if err != nil {
		slog.Warn("refresh machine status failed", "machine", name, "error", err)
		return
	}
	if serr := e.store.SetStatus(ctx, name, MapVBoxState(info.State)); serr != nil {
		slog.Error("record machine status", "machine", name, "error", serr)
	}
}

// start boots a machine — the Node agent's executeStartTask (`zoneadm boot`)
// spoken in VBoxManage: `startvm --type headless`, then record the live
// status. Immediate; no provisioning machinery involved (Mark's ruling,
// 2026-07-05: lifecycle is hypervisor commands only).
func (e *executors) start(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	out.Write("stdout", "Starting "+machine.Name+" (VBoxManage startvm --type headless)\n")
	if serr := vbox.StartVM(ctx, vboxExe, machine.Name, false); serr != nil {
		out.Write("stderr", "Failed to start machine "+machine.Name+": "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Machine "+machine.Name+" started successfully\n")
	return nil
}

// cancelStart is the start operation's post-kill cleanup (D-F): force the
// half-started VM off so it is not left running unattended.
func (e *executors) cancelStart(task *tasks.Task, out *tasks.OutputWriter) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	exe := VBoxManagePath(ctx)
	if exe == "" {
		return
	}
	out.Write("stderr", "Start cancelled — forcing the machine off\n")
	if err := vbox.ControlVM(ctx, exe, task.MachineName, "poweroff"); err != nil {
		// Never-booted machines have nothing to power off; that is success.
		out.Write("stderr", "Power off after cancel: "+err.Error()+"\n")
	}
	e.refreshStatus(task.MachineName, exe)
}

// stop halts a machine — the Node agent's executeStopTask (graceful
// `zoneadm shutdown`, falling back to `zoneadm halt`) spoken in VBoxManage:
// ACPI power button first, hard poweroff when the guest ignores it or when
// the request forced.
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

	if !meta.Force {
		out.Write("stdout", "Stopping "+machine.Name+" gracefully (ACPI power button)\n")
		if aerr := vbox.ControlVM(ctx, vboxExe, machine.Name, "acpipowerbutton"); aerr == nil {
			if e.waitForPowerOff(ctx, vboxExe, machine.Name, out) {
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

	if perr := vbox.ControlVM(ctx, vboxExe, machine.Name, "poweroff"); perr != nil {
		out.Write("stderr", "Failed to stop machine "+machine.Name+": "+perr.Error()+"\n")
		return perr
	}
	out.Write("stdout", "Machine "+machine.Name+" stopped successfully\n")
	return nil
}

// waitForPowerOff polls until an ACPI-signalled machine leaves the running
// state (the synchronous-shutdown semantics of `zoneadm shutdown`). False on
// timeout — the caller falls back to a hard poweroff, like zoneadm halt.
func (e *executors) waitForPowerOff(ctx context.Context, vboxExe, name string, out *tasks.OutputWriter) bool {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
		info, err := vbox.ShowVMInfo(ctx, vboxExe, name)
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

// suspend saves a machine's state — `controlvm savestate` (no zone analog;
// VirtualBox capability advertised by the machine-suspend token).
func (e *executors) suspend(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	out.Write("stdout", "Suspending "+machine.Name+" (VBoxManage savestate)\n")
	if serr := vbox.ControlVM(ctx, vboxExe, machine.Name, "savestate"); serr != nil {
		out.Write("stderr", "Failed to suspend machine "+machine.Name+": "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Machine "+machine.Name+" suspended successfully\n")
	return nil
}

// deleteMachine destroys a machine — the Node agent's executeDeleteTask
// (halt → uninstall -F → zonecfg delete -F → registry cleanup) spoken in
// VBoxManage: power off if running, unregister with media deletion, remove
// the registry row, cancel leftover pending tasks.
func (e *executors) deleteMachine(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}

	// Power off if something is still running, then unregister with media
	// deletion.
	info, ierr := vbox.ShowVMInfo(ctx, vboxExe, machine.Name)
	if ierr == nil {
		if MapVBoxState(info.State) == StatusRunning {
			out.Write("stdout", "Powering off "+machine.Name+" before unregistering\n")
			if perr := vbox.ControlVM(ctx, vboxExe, machine.Name, "poweroff"); perr != nil {
				out.Write("stderr", "Power off failed: "+perr.Error()+"\n")
			}
		}
		out.Write("stdout", "Unregistering "+machine.Name+" from VirtualBox (deleting media)\n")
		if uerr := vbox.UnregisterVM(ctx, vboxExe, machine.Name, true); uerr != nil {
			return uerr
		}
	} else if !errors.Is(ierr, vbox.ErrNotFound) {
		return ierr
	}

	out.Write("stdout", "Removing "+machine.Name+" from the registry\n")
	if derr := e.store.Delete(ctx, machine.Name); derr != nil && !errors.Is(derr, ErrNotFound) {
		return derr
	}

	// The Node agent's delete finisher: any remaining pending tasks for the
	// machine are cancelled — they target something that no longer exists.
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

// discover runs one reconciliation sweep as a queued task — the ONLY way a
// sweep runs (Node-agent parity: startup, periodic, and user-triggered
// discovery all share this operation and are all visible in the queue).
func (e *executors) discover(ctx context.Context, _ *tasks.Task, out *tasks.OutputWriter) error {
	out.Write("stdout", "Reconciling registry against VirtualBox and vagrant\n")
	e.reconciler.RunOnce(ctx, out)
	return nil
}
