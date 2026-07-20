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

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

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
	if e.dispatchUTM(ctx, task) {
		return e.deleteMachineUTM(ctx, task, out)
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}

	meta := deleteMetadata{CleanupDisks: true}
	if len(task.Metadata) > 0 {
		if uerr := json.Unmarshal(task.Metadata, &meta); uerr != nil {
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

	return e.deleteRegistryTail(ctx, machine, meta.CleanupDisks, out)
}

// deleteMachineUTM is deleteMachine's utm branch: status probe, force-stop
// when running, utm.Delete — the .utm bundle ALWAYS dies with the machine
// (UTM owns its storage); cleanup_disks governs only the agent's working
// directory. DHCP-lease removal and foreign-media detach are VBox plumbing
// utm machines never carry.
func (e *executors) deleteMachineUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
	if err != nil {
		return err
	}

	meta := deleteMetadata{CleanupDisks: true}
	if len(task.Metadata) > 0 {
		if uerr := json.Unmarshal(task.Metadata, &meta); uerr != nil {
			return fmt.Errorf("parse delete metadata: %w", uerr)
		}
	}

	target := machine.VBoxTarget()
	status, serr := utm.Status(ctx, utmctlPath, target)
	if serr == nil {
		if utm.MapUTMState(status) == StatusRunning {
			out.Write("stdout", "Powering off "+machine.Name+" before deleting\n")
			if perr := utm.Stop(ctx, utmctlPath, target, true); perr != nil {
				out.Write("stderr", "Power off failed: "+perr.Error()+"\n")
			}
		}
		if meta.CleanupDisks {
			out.Write("stdout", "Deleting "+machine.Name+" from UTM (the .utm bundle dies with it)\n")
		} else {
			out.Write("stdout", "Deleting "+machine.Name+" from UTM — the .utm bundle dies with it regardless; cleanup_disks=false preserves only the working directory\n")
		}
		if derr := utm.Delete(ctx, utmctlPath, target); derr != nil {
			return derr
		}
	} else {
		// utmctl's not-found text is unmapped — a failed probe reads as no VM
		// behind the row (the VBox ErrNotFound path); the tail still runs.
		out.Write("stderr", "UTM status probe failed ("+serr.Error()+") — treating the VM as already gone\n")
	}

	return e.deleteRegistryTail(ctx, machine, meta.CleanupDisks, out)
}

// deleteRegistryTail closes both hypervisors' delete paths: the working
// directory (honoring cleanup_disks), the registry row, and the machine's
// leftover pending tasks.
func (e *executors) deleteRegistryTail(ctx context.Context, machine *Machine, cleanupDisks bool, out *tasks.OutputWriter) error {
	if cleanupDisks {
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
