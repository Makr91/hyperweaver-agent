package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// start boots a machine: `VBoxManage startvm --type headless` — one native
// path for every machine (the provision pipeline queues this same operation
// as its boot child).
func (e *executors) start(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.startUTM(ctx, task, out)
	}
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

// startUTM boots a utm machine (utmctl start — the same verb resumes paused
// machines). VBoxTarget's UUID-else-name rule addresses utmctl too.
func (e *executors) startUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatusUTM(machine.Name, utmctlPath)

	out.Write("stdout", "Starting "+machine.Name+" (utmctl start)\n")
	if serr := utm.Start(ctx, utmctlPath, machine.VBoxTarget()); serr != nil {
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

	if e.dispatchUTM(ctx, task) {
		e.cancelStartUTM(ctx, task, out)
		return
	}

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

// cancelStartUTM is cancelStart's utm branch: a best-effort forced stop.
func (e *executors) cancelStartUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) {
	utmctlPath := UTMCtlPath(ctx)
	if utmctlPath == "" {
		return
	}
	target := task.MachineName
	if machine, err := e.store.Get(ctx, task.MachineName); err == nil {
		target = machine.VBoxTarget()
	}
	out.Write("stderr", "Start cancelled — forcing the machine off\n")
	if err := utm.Stop(ctx, utmctlPath, target, true); err != nil {
		// Never-booted machines have nothing to power off; that is success.
		out.Write("stderr", "Power off after cancel: "+err.Error()+"\n")
	}
	e.refreshStatusUTM(task.MachineName, utmctlPath)
}

// stop halts a machine: ACPI power button first, hard poweroff when the
// guest ignores it or when the request forced.
func (e *executors) stop(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.stopUTM(ctx, task, out)
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatus(machine.Name, vboxExe)

	var meta stopMetadata
	if len(task.Metadata) > 0 {
		if uerr := json.Unmarshal(task.Metadata, &meta); uerr != nil {
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

// stopUTM halts a utm machine — the utm stop ladder: paused machines resume
// first (utmctl stop does not take on a paused machine; utmctl start resumes
// them), graceful stop, wait for stopped, Stop force on timeout or force
// request. The guest-agent rung does not exist here — that is VBox COM2
// UART plumbing utm machines never carry.
func (e *executors) stopUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatusUTM(machine.Name, utmctlPath)

	var meta stopMetadata
	if len(task.Metadata) > 0 {
		if uerr := json.Unmarshal(task.Metadata, &meta); uerr != nil {
			return fmt.Errorf("parse stop metadata: %w", uerr)
		}
	}

	target := machine.VBoxTarget()
	if !meta.Force {
		if status, serr := utm.Status(ctx, utmctlPath, target); serr == nil &&
			utm.MapUTMState(status) == StatusPaused {
			out.Write("stdout", "Machine is paused — resuming first (utmctl stop does not take on a paused machine)\n")
			if rerr := utm.Start(ctx, utmctlPath, target); rerr != nil {
				out.Write("stderr", "Resume before stop failed: "+rerr.Error()+"\n")
			}
		}
		if gerr := utm.Stop(ctx, utmctlPath, target, false); gerr == nil {
			out.Write("stdout", "Stopping "+machine.Name+" gracefully (utmctl stop)\n")
			if e.waitForPowerOffUTM(ctx, utmctlPath, target, out) {
				out.Write("stdout", "Machine "+machine.Name+" stopped successfully\n")
				return nil
			}
			out.Write("stderr", "Graceful shutdown did not complete; forcing power off\n")
		} else {
			out.Write("stderr", "Graceful stop failed ("+gerr.Error()+"); forcing power off\n")
		}
	} else {
		out.Write("stdout", "Stopping "+machine.Name+" (forced)\n")
	}

	if perr := utm.Stop(ctx, utmctlPath, target, true); perr != nil {
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

// waitForPowerOffUTM is waitForPowerOff's utm twin, polling utmctl status
// against the same machines.shutdown_timeout.
func (e *executors) waitForPowerOffUTM(ctx context.Context, utmctlPath, target string, out *tasks.OutputWriter) bool {
	deadline := time.Now().Add(e.shutdownTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(3 * time.Second):
		}
		status, err := utm.Status(ctx, utmctlPath, target)
		if err != nil {
			return false
		}
		if utm.MapUTMState(status) != StatusRunning {
			out.Write("stdout", "Machine reports state: "+status+"\n")
			return true
		}
	}
	return false
}

// suspend saves a machine's state (`controlvm savestate`).
func (e *executors) suspend(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.suspendUTM(ctx, task, out)
	}
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

// suspendUTM pauses a utm machine (utmctl suspend). UTM has ONE pause
// concept — no distinct pause-to-disk — so suspend and pause ride the same
// verb there.
func (e *executors) suspendUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatusUTM(machine.Name, utmctlPath)

	out.Write("stdout", "Suspending "+machine.Name+" (utmctl suspend)\n")
	if serr := utm.Suspend(ctx, utmctlPath, machine.VBoxTarget()); serr != nil {
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
		if e.dispatchUTM(ctx, task) {
			return e.controlActionUTM(ctx, task, operation, out)
		}
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

// controlActionUTM answers the controlvm verbs on utm machines: pause rides
// utmctl suspend (UTM has one pause concept — suspend IS pause there),
// resume rides utmctl start (start resumes paused machines), and reset is
// refused — utmctl has no reset verb.
func (e *executors) controlActionUTM(ctx context.Context, task *tasks.Task, operation string, out *tasks.OutputWriter) error {
	if operation == OpReset {
		return errors.New("reset is not supported on utm machines — stop and start instead")
	}
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}
	defer e.refreshStatusUTM(machine.Name, utmctlPath)

	target := machine.VBoxTarget()
	switch operation {
	case OpPause:
		out.Write("stdout", "Running pause on "+machine.Name+" (utmctl suspend)\n")
		err = utm.Suspend(ctx, utmctlPath, target)
	case OpResume:
		out.Write("stdout", "Running resume on "+machine.Name+" (utmctl start)\n")
		err = utm.Start(ctx, utmctlPath, target)
	}
	if err != nil {
		out.Write("stderr", "Failed to "+operation+" machine "+machine.Name+": "+err.Error()+"\n")
		return err
	}
	out.Write("stdout", "Machine "+machine.Name+" "+operation+" completed\n")
	return nil
}
