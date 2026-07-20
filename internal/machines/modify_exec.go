package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The modify executor — zoneweaver's ZoneModificationManager
// (ZoneModifyOrchestrator + ZoneAttributeModifier/ZoneNetworkModifier/
// ZoneStorageModifier) spoken in VBoxManage. The task metadata is the PUT
// body verbatim (the base's rule); each change family applies in its own
// step, and the row's configuration re-syncs from the live view at the end
// (syncZoneToDatabase's merge — the stored document sections survive).
//
// One platform difference the wire's requires_restart:true conveys: zonecfg
// edits the offline configuration while the zone runs; VirtualBox has no
// offline store — modifyvm/storageattach demand a powered-off machine, so
// the executor refuses anything else instead of retrying into the session
// lock.

// OpModify is the modification task operation (the base's zone_modify).
const OpModify = "machine_modify"

// modifyMachine executes machine_modify: attribute scalars, autoboot, NIC
// add/remove, disk/cdrom add/remove, cloud-init properties, then the
// database re-sync (executeZoneModifyTask's exact order).
func (e *executors) modifyMachine(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if e.dispatchUTM(ctx, task) {
		return e.modifyMachineUTM(ctx, task, out)
	}
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	if len(task.Metadata) == 0 {
		return errors.New("modify task has no metadata")
	}
	metadata := map[string]any{}
	if uerr := json.Unmarshal(task.Metadata, &metadata); uerr != nil {
		return fmt.Errorf("parse modify metadata: %w", uerr)
	}

	e.taskProgress(task, 10, "reading_configuration")
	target := machine.VBoxTarget()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, target)
	if errors.Is(err, vbox.ErrNotFound) {
		return errors.New("no VM exists behind this machine yet — infrastructure changes apply after create builds it")
	}
	if err != nil {
		return err
	}
	switch MapVBoxState(info.State) {
	case StatusStopped, StatusAborted:
	default:
		return fmt.Errorf("machine is %s — VirtualBox only modifies powered-off machines; stop it and the queued change can re-run", info.State)
	}

	changes := []string{}

	attrFlags, notes, aerr := modifyAttributeFlags(metadata, info)
	if aerr != nil {
		return aerr
	}
	for _, note := range notes {
		out.Write("stderr", note+"\n")
	}
	if len(attrFlags) > 0 {
		e.taskProgress(task, 20, "modifying_attributes")
		if merr := vbox.ModifyVM(ctx, vboxExe, target, attrFlags); merr != nil {
			return fmt.Errorf("attribute modification failed: %w", merr)
		}
		changes = append(changes, "attributes")
	}

	if raw, ok := metadata["autoboot"]; ok {
		e.taskProgress(task, 40, "modifying_autoboot")
		if merr := vbox.ModifyVM(ctx, vboxExe, target,
			[]string{"--autostart-enabled=" + onOff(raw)}); merr != nil {
			return fmt.Errorf("autoboot modification failed: %w", merr)
		}
		changes = append(changes, "autoboot")
	}

	// guest_agent as a MODIFY toggle (Mark's Proxmox-model ruling 2026-07-12):
	// true wires the QGA UART (COM2 → the machine's deterministic pipe), false
	// removes that device — accrued/queued like every infrastructure field and
	// applied at the power cycle, exactly Proxmox's pending "QEMU Agent"
	// checkbox. The sweep's guest_info probe then keeps calling the channel
	// until the guest answers. hardware.serial claiming port 2 in the same
	// request wins (the create-time collision rule).
	if raw, ok := metadata["guest_agent"]; ok {
		e.taskProgress(task, 45, "modifying_guest_agent")
		if serialPortClaimed(mapOr(metadata["vbox"]), 2) {
			out.Write("stderr", "guest_agent skipped — vbox.serial claims port 2 in the same request (the document wins)\n")
		} else {
			var uartFlags []string
			if onOff(raw) == "on" {
				workdir := e.machineWorkdir(machine.Name)
				if machine.Home != nil && *machine.Home != "" {
					workdir = *machine.Home
				}
				pipe := qga.PipePath(workdir, machine.Name)
				uartFlags = []string{"--uart2", "0x2F8", "3", "--uart-mode2", "server", pipe}
				out.Write("stdout", "Guest-agent channel: COM2 → "+pipe+"\n")
			} else {
				uartFlags = []string{"--uart2=off"}
				out.Write("stdout", "Guest-agent UART removed\n")
			}
			if merr := vbox.ModifyVM(ctx, vboxExe, target, uartFlags); merr != nil {
				return fmt.Errorf("guest_agent modification failed: %w", merr)
			}
			changes = append(changes, "guest_agent")
		}
	}

	if cerr := e.modifyNetworks(ctx, task, vboxExe, target, info, metadata, &changes, out); cerr != nil {
		return cerr
	}
	if cerr := e.modifyStorage(ctx, task, vboxExe, target, machine.Name, info, metadata, &changes, out); cerr != nil {
		return cerr
	}

	if cloudInit := mapOr(metadata["cloud_init"]); len(cloudInit) > 0 {
		e.taskProgress(task, 85, "modifying_cloud_init")
		for key, value := range cloudInit {
			if s := stringOr(value, ""); s != "" {
				if perr := vbox.SetGuestProperty(ctx, vboxExe, target,
					"/Hyperweaver/CloudInit/"+key, s); perr != nil {
					return fmt.Errorf("cloud-init modification failed: %w", perr)
				}
			}
		}
		changes = append(changes, "cloud_init")
	}

	e.taskProgress(task, 95, "updating_database_configuration")
	e.syncLiveConfiguration(ctx, machine.Name, vboxExe, target, out)
	e.refreshStatus(machine.Name, vboxExe)

	// Accrued pending changes (the _apply_pending marker) clear on success —
	// a failed apply keeps them pending for the next power cycle.
	if applied, _ := metadata["_apply_pending"].(bool); applied {
		if cerr := e.store.ClearPendingChanges(ctx, machine.Name); cerr != nil {
			out.Write("stderr", "Pending-changes clear failed (they will re-apply next cycle): "+cerr.Error()+"\n")
		} else {
			out.Write("stdout", "Accrued pending changes applied and cleared.\n")
		}
	}

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+machine.Name+" modified successfully ("+
		strings.Join(changes, ", ")+"). Changes take effect on next start.\n")
	return nil
}

// syncLiveConfiguration re-reads the live view and merges it around the
// stored document sections (syncZoneToDatabase + preserveUserConfig — the
// discovery merge applied immediately). Failure warns and never fails the
// modification: the next reconciliation sweep repairs it.
func (e *executors) syncLiveConfiguration(ctx context.Context, machineName, vboxExe, target string, out *tasks.OutputWriter) {
	fresh, err := vbox.ShowVMInfo(ctx, vboxExe, target)
	if err != nil {
		out.Write("stderr", "Live configuration re-read failed (the next discovery sweep repairs it): "+err.Error()+"\n")
		return
	}
	live, err := json.Marshal(fresh.Raw)
	if err != nil {
		return
	}
	machine, err := e.store.Get(ctx, machineName)
	if err != nil {
		return
	}
	merged := MergeLiveConfiguration(machine.Configuration, live)
	if serr := e.store.SetConfiguration(ctx, machineName, merged); serr != nil {
		out.Write("stderr", "Configuration re-sync failed: "+serr.Error()+"\n")
	}
}

// onOff coerces the base's on/off attribute values (strings or booleans)
// into modifyvm's on|off vocabulary.
func onOff(value any) string {
	if b, ok := value.(bool); ok {
		if b {
			return "on"
		}
		return "off"
	}
	switch strings.ToLower(stringOr(value, "")) {
	case "on", "true", "1", "yes":
		return "on"
	}
	return "off"
}

// portNumber parses a remove-entry into a number: bare numbers and numeric
// strings ONLY. The base's attribute-name shape (disk0, cdrom1) is
// deliberately rejected — its disk numbering starts at the first ADDITIONAL
// disk while this agent's port 0 is the boot medium, so a silent name→port
// mapping would be off by one against the boot disk.
func portNumber(value any) (n int, ok bool) {
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return parsed, true
		}
	}
	return 0, false
}
