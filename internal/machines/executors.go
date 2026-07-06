package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vagrant"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Machine lifecycle operations (task queue vocabulary, Node-agent parity).
// The machine_* operations are the provisioned start pipeline's children
// (zoneweaver's zone_create_* sub-task model): chained under a start parent
// anchor whose aggregation IS the coarse progress.
const (
	OpStart       = "start"
	OpStop        = "stop"
	OpRestart     = "restart" // never dispatched: a restart is a stop→start chain
	OpSuspend     = "suspend"
	OpDelete      = "delete"
	OpDiscover    = "discover"
	OpProvision   = "provision"
	OpSync        = "sync"
	OpPrepare     = "machine_prepare"
	OpPluginCheck = "machine_plugin_check"
	OpVagrantUp   = "machine_vagrant_up"
)

// stopMetadata is the stop/delete task metadata document.
type stopMetadata struct {
	Force bool `json:"force"`
}

// RegisterExecutors wires the machine lifecycle operations into the task
// queue. Lifecycle is dual-path (the provisioning phase's completion of
// Mark's 2026-07-05 ruling): machines carrying a creation spec start
// through vagrant — the pipeline in provisioned.go, where the unchanged
// Hosts.rb does the real work — while raw machines and all power-down
// actions speak VBoxManage directly. shutdownTimeout is the graceful-stop
// ACPI grace window (the Node agent's
// zones.orchestration.timeouts.zone_shutdown).
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
	queue.Register(OpProvision, tasks.Executor{Run: e.provision})
	queue.Register(OpSync, tasks.Executor{Run: e.sync})
	queue.Register(OpPrepare, tasks.Executor{Run: e.prepare})
	queue.Register(OpPluginCheck, tasks.Executor{Run: e.pluginCheck})
	queue.Register(OpVagrantUp, tasks.Executor{Run: e.vagrantUp, OnCancel: e.cancelStart})
}

type executors struct {
	queue           *tasks.Queue
	store           *Store
	reconciler      *Reconciler
	shutdownTimeout time.Duration
	env             *ProvisionEnv
}

// provision runs `vagrant provision` after re-rendering the working copy.
func (e *executors) provision(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	return e.runVagrantOp(ctx, task, out, "provision", vagrant.Provision)
}

// sync runs `vagrant rsync` (the literal subcommand — SHI's rsync-arg bug
// stays dead).
func (e *executors) sync(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	return e.runVagrantOp(ctx, task, out, "rsync", vagrant.Rsync)
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
// targeted showvminfo refresh). The row is reloaded first so the freshest
// UUID addresses the VM — a provisioned machine's VirtualBox name is never
// its registry name.
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

// start boots a machine, dual-path: a provisioned machine (spec + working
// directory) goes through the vagrant pipeline — render, materialize,
// plugin check, `vagrant up` — so the unchanged Hosts.rb builds the VM and
// runs the collections; a raw machine is an immediate `VBoxManage startvm
// --type headless`.
func (e *executors) start(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	if machine.Provisioned() {
		return e.startProvisioned(ctx, task, machine, out)
	}

	out.Write("stdout", "Starting "+machine.Name+" (VBoxManage startvm --type headless)\n")
	if serr := vbox.StartVM(ctx, vboxExe, machine.VBoxTarget(), false); serr != nil {
		out.Write("stderr", "Failed to start machine "+machine.Name+": "+serr.Error()+"\n")
		return serr
	}
	out.Write("stdout", "Machine "+machine.Name+" started successfully\n")
	return nil
}

// cancelStart is the start operation's post-kill cleanup (D-F, SHI's
// stop-during-up semantics): the killed vagrant/VBox child leaves a half-up
// VM — force it off so it is not left running unattended. For provisioned
// machines the working directory's vagrant state carries the fresh UUID the
// killed up may have just created.
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
		if machine.Provisioned() {
			if uuid := vagrantMachineUUID(*machine.Home); uuid != "" {
				target = uuid
				if machine.UUID == nil || *machine.UUID != uuid {
					if serr := e.store.SetUUID(ctx, machine.Name, uuid); serr != nil {
						mlog().Error("record machine uuid after cancel", "machine", machine.Name, "error", serr)
					}
				}
			}
		}
	}
	out.Write("stderr", "Start cancelled — forcing the machine off\n")
	if err := vbox.ControlVM(ctx, exe, target, "poweroff"); err != nil {
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
// state (the synchronous-shutdown semantics of `zoneadm shutdown`), bounded
// by machines.shutdown_timeout. False on timeout — the caller falls back to
// a hard poweroff, like zoneadm halt.
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

// suspend saves a machine's state — `controlvm savestate` (no zone analog;
// VirtualBox capability advertised by the machine-suspend token).
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

// deleteMachine destroys a machine — the Node agent's executeDeleteTask
// shape, completed for the provisioning phase (design §4): provisioned
// machines get `vagrant destroy -f` first (vagrant state cleaned by its
// owner), then the VBoxManage sweep — power off if running, unregister with
// media deletion — the working-directory removal, the registry row, and the
// leftover pending tasks.
func (e *executors) deleteMachine(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}

	if machine.Provisioned() {
		if vagrantExe := VagrantPath(ctx); vagrantExe != "" {
			out.Write("stdout", "Running vagrant destroy -f in "+*machine.Home+"\n")
			if derr := vagrant.Destroy(ctx, vagrantExe, *machine.Home, out.Write); derr != nil {
				out.Write("stderr", "vagrant destroy failed ("+derr.Error()+") — continuing with VBoxManage cleanup\n")
			}
		} else {
			out.Write("stderr", "vagrant is not installed — continuing with VBoxManage cleanup\n")
		}
	}

	// Power off if something is still running, then unregister with media
	// deletion.
	target := machine.VBoxTarget()
	info, ierr := vbox.ShowVMInfo(ctx, vboxExe, target)
	if ierr == nil {
		if MapVBoxState(info.State) == StatusRunning {
			out.Write("stdout", "Powering off "+machine.Name+" before unregistering\n")
			if perr := vbox.ControlVM(ctx, vboxExe, target, "poweroff"); perr != nil {
				out.Write("stderr", "Power off failed: "+perr.Error()+"\n")
			}
		}
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
