package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
)

// utmDiskFamilies and utmNoAnalogKeys split the modify vocabulary on utm:
// the disk families are a HARD refusal (UTM's scripting API exposes no
// drives), the rest narrate as skipped.
var (
	utmDiskFamilies = []string{
		"add_disks", "remove_disks", "add_cdroms", "remove_cdroms",
		"add_controllers", "remove_controllers",
	}
	utmNoAnalogKeys = []string{
		"os_type", "vnc", "acpi", "xhci", "bootrom", "hostbridge", "netif",
		"diskif", "boot_order", "autoboot", "guest_agent", "cloud_init", "vbox",
	}
)

// modifyMachineUTM is machine_modify's utm branch — the same stopped-gate
// contract spoken through UTM's scripting API: Customize carries ram/vcpus
// and the utm section's notes, qemu_args[] append verbatim, the NIC families
// ride QEMU-arg pairs and SetMACAddress. Disk changes are refused whole
// BEFORE anything applies; no live-config re-sync exists (UTM has no
// machinereadable analog) — refreshStatusUTM records the state.
func (e *executors) modifyMachineUTM(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, utmctlPath, err := e.resolveUTM(ctx, task)
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
	status, serr := utm.Status(ctx, utmctlPath, target)
	if serr != nil {
		if machine.UUID == nil {
			return errors.New("no VM exists behind this machine yet — infrastructure changes apply after create builds it")
		}
		return serr
	}
	if utm.MapUTMState(status) != StatusStopped {
		return fmt.Errorf("machine is %s — UTM only modifies stopped machines; stop it and the queued change can re-run", status)
	}

	for _, key := range utmDiskFamilies {
		if _, ok := metadata[key]; ok {
			return errors.New("UTM's scripting API does not expose drives — disk changes are not possible on utm machines")
		}
	}
	for _, key := range utmNoAnalogKeys {
		if _, ok := metadata[key]; ok {
			out.Write("stderr", key+" has no UTM scripting analog — skipped\n")
		}
	}

	changes := []string{}
	utmSection := mapOr(metadata["utm"])
	opts := utm.CustomizeOptions{Notes: stringOr(utmSection["notes"], "")}
	if v, ok := metadata["ram"]; ok {
		opts.MemoryMB = int(memoryToMB(v))
	}
	if v, ok := metadata["vcpus"]; ok {
		opts.CPUs = int(VCPUCount(v, 2))
	}
	if opts != (utm.CustomizeOptions{}) {
		e.taskProgress(task, 20, "modifying_attributes")
		if cerr := utm.Customize(ctx, target, opts); cerr != nil {
			return fmt.Errorf("attribute modification failed: %w", cerr)
		}
		changes = append(changes, "attributes")
	}

	qemuArgs := []string{}
	for _, entry := range listOr(utmSection["qemu_args"]) {
		if arg := stringOr(entry, ""); arg != "" {
			qemuArgs = append(qemuArgs, arg)
		}
	}
	if len(qemuArgs) > 0 {
		e.taskProgress(task, 40, "adding_qemu_args")
		if aerr := utm.AddQemuArgs(ctx, target, qemuArgs); aerr != nil {
			return fmt.Errorf("qemu args modification failed: %w", aerr)
		}
		changes = append(changes, "qemu_args")
	}

	if cerr := e.modifyNetworksUTM(ctx, task, target, metadata, &changes, out); cerr != nil {
		return cerr
	}

	e.taskProgress(task, 95, "updating_database_configuration")
	e.refreshStatusUTM(machine.Name, utmctlPath)

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

var utmNetdevIDForm = regexp.MustCompile(`^net\d+$`)

// qemuArgCarriesNetID reports whether a QEMU argument names the netdev id
// (id=<id> on -netdev lines, netdev=<id> on -device lines — exact, so net2
// never matches net20).
func qemuArgCarriesNetID(arg, id string) bool {
	for _, key := range []string{"id=", "netdev="} {
		idx := strings.Index(arg, key+id)
		if idx < 0 {
			continue
		}
		rest := arg[idx+len(key)+len(id):]
		if rest == "" || strings.HasPrefix(rest, ",") || strings.HasPrefix(rest, " ") {
			return true
		}
	}
	return false
}

// modifyNetworksUTM handles the NIC families on utm: add_nics become vmnet
// QEMU-arg pairs on the next free netN ids (net2 up — net0/net1 are the box's
// shared+emulated base pair), remove_nics name netN ids whose -netdev/-device
// lines are removed, and nics[] tuning applies mac only (no other knob has a
// UTM analog).
func (e *executors) modifyNetworksUTM(ctx context.Context, task *tasks.Task, target string,
	metadata map[string]any, changes *[]string, out *tasks.OutputWriter,
) error {
	if addNICs := listOr(metadata["add_nics"]); len(addNICs) > 0 {
		e.taskProgress(task, 50, "adding_nics")
		existing, err := utm.ReadQemuNetdevIDs(ctx, target)
		if err != nil {
			return fmt.Errorf("failed to read netdev ids: %w", err)
		}
		used := map[string]bool{}
		for _, id := range existing {
			used[id] = true
		}
		next := 2
		qemuArgs := []string{}
		for _, entry := range addNICs {
			nic := mapOr(entry)
			for used["net"+strconv.Itoa(next)] {
				next++
			}
			netID := "net" + strconv.Itoa(next)
			used[netID] = true
			netdev := "-netdev vmnet-shared,id=" + netID
			if bridge := stringOr(nic["global_nic"], ""); bridge != "" {
				netdev = "-netdev vmnet-bridged,id=" + netID + ",ifname=" + bridge
			}
			mac := stringOr(nic["mac_addr"], "")
			if mac == "" {
				mac = utm.RandomMAC()
			}
			qemuArgs = append(qemuArgs, netdev, "-device virtio-net-pci,mac="+mac+",netdev="+netID)
			for key := range nic {
				switch key {
				case "global_nic", "mac_addr":
				default:
					out.Write("stderr", "add_nics."+key+" has no UTM scripting analog — skipped\n")
				}
			}
			out.Write("stdout", "Adding NIC "+netID+" ("+netdev+")\n")
		}
		if aerr := utm.AddQemuArgs(ctx, target, qemuArgs); aerr != nil {
			return fmt.Errorf("failed to add NICs: %w", aerr)
		}
		*changes = append(*changes, "add_nics")
	}

	if removeNICs := listOr(metadata["remove_nics"]); len(removeNICs) > 0 {
		e.taskProgress(task, 55, "removing_nics")
		lines, err := utm.ReadQemuArgs(ctx, target)
		if err != nil {
			return fmt.Errorf("failed to read qemu args: %w", err)
		}
		toRemove := []string{}
		for _, entry := range removeNICs {
			id := stringOr(entry, "")
			if !utmNetdevIDForm.MatchString(id) {
				return fmt.Errorf("remove_nics entries on utm machines name netdev ids like net2 (got %v)", entry)
			}
			matched := false
			for _, line := range lines {
				if qemuArgCarriesNetID(line, id) {
					toRemove = append(toRemove, line)
					matched = true
				}
			}
			if !matched {
				return fmt.Errorf("no QEMU network arguments carry id %s", id)
			}
			out.Write("stdout", "Removing NIC "+id+"\n")
		}
		if rerr := utm.RemoveQemuArgs(ctx, target, toRemove); rerr != nil {
			return fmt.Errorf("failed to remove NICs: %w", rerr)
		}
		*changes = append(*changes, "remove_nics")
	}

	if tuning := listOr(metadata["nics"]); len(tuning) > 0 {
		e.taskProgress(task, 57, "tuning_nics")
		applied := false
		for _, entry := range tuning {
			nic := mapOr(entry)
			adapter := int(intOr(nic["adapter"], -1))
			if adapter < 0 {
				return fmt.Errorf("nics entries on utm machines need adapter (the interface index, 0-based) (got %v)", nic["adapter"])
			}
			if mac := stringOr(nic["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
				if merr := utm.SetMACAddress(ctx, target, adapter, mac); merr != nil {
					return fmt.Errorf("failed to tune NICs: %w", merr)
				}
				out.Write("stdout", fmt.Sprintf("Interface %d MAC set to %s\n", adapter, mac))
				applied = true
			}
			for key := range nic {
				switch key {
				case "adapter", "mac":
				default:
					out.Write("stderr", "nics."+key+" has no UTM scripting analog — skipped\n")
				}
			}
		}
		if applied {
			*changes = append(*changes, "nics")
		}
	}
	return nil
}
