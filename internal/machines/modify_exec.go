package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	if task.Metadata == nil {
		return errors.New("modify task has no metadata")
	}
	metadata := map[string]any{}
	if uerr := json.Unmarshal([]byte(*task.Metadata), &metadata); uerr != nil {
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
		if serialPortClaimed(mapOr(metadata["hardware"]), 2) {
			out.Write("stderr", "guest_agent skipped — hardware.serial claims port 2 in the same request (the document wins)\n")
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

// ValidateModifyDocument dry-runs the modify translation — the accrue path's
// PUT-time validation: unknown hardware sections/knobs and malformed
// serial/parallel entries reject at the PUT instead of at apply time.
func ValidateModifyDocument(metadata map[string]any, info *vbox.Info) error {
	_, _, err := modifyAttributeFlags(metadata, info)
	return err
}

// modifyNetworks handles add_nics/remove_nics (handleNetworkModifications):
// added NICs land on the first free adapters (bridged; global_nic is the
// bridge interface — the base's meaning); removals name adapter numbers.
func (e *executors) modifyNetworks(ctx context.Context, task *tasks.Task, vboxExe, target string,
	info *vbox.Info, metadata map[string]any, changes *[]string, out *tasks.OutputWriter,
) error {
	if addNICs := listOr(metadata["add_nics"]); len(addNICs) > 0 {
		e.taskProgress(task, 50, "adding_nics")
		free := freeNICSlots(info)
		if len(addNICs) > len(free) {
			return fmt.Errorf("cannot add %d NICs — only %d free adapters (VirtualBox caps at %d)",
				len(addNICs), len(free), maxNICSlots)
		}
		flags := []string{}
		for i, entry := range addNICs {
			nic := mapOr(entry)
			n := strconv.Itoa(free[i])
			flags = append(flags, "--nic"+n+"=bridged")
			if bridge := stringOr(nic["global_nic"], ""); bridge != "" {
				flags = append(flags, "--bridge-adapter"+n+"="+bridge)
			}
			if mac := stringOr(nic["mac_addr"], ""); mac != "" {
				flags = append(flags, "--mac-address"+n+"="+strings.ReplaceAll(mac, ":", ""))
			}
			// The nics[] tuning keys ride INLINE on add_nics entries (the
			// unified adapter editor's ask: only the agent knows the new
			// adapter's slot, so the tuning must land in the same operation).
			flags = append(flags, nicExtraFlags(nic, n)...)
			if _, ok := nic["vlan_id"]; ok {
				out.Write("stderr", "add_nics.vlan_id has no VirtualBox bridged-adapter analog — skipped\n")
			}
			if _, ok := nic["allowed_address"]; ok {
				out.Write("stderr", "add_nics.allowed_address has no VirtualBox analog — skipped\n")
			}
		}
		if merr := vbox.ModifyVM(ctx, vboxExe, target, flags); merr != nil {
			return fmt.Errorf("failed to add NICs: %w", merr)
		}
		*changes = append(*changes, "add_nics")
	}

	if removeNICs := listOr(metadata["remove_nics"]); len(removeNICs) > 0 {
		e.taskProgress(task, 55, "removing_nics")
		flags := []string{}
		for _, entry := range removeNICs {
			adapter, ok := portNumber(entry)
			if !ok || adapter < 1 || adapter > maxNICSlots {
				return fmt.Errorf("remove_nics entries name adapter numbers 1-%d (got %v)", maxNICSlots, entry)
			}
			flags = append(flags, "--nic"+strconv.Itoa(adapter)+"=none")
		}
		if merr := vbox.ModifyVM(ctx, vboxExe, target, flags); merr != nil {
			return fmt.Errorf("failed to remove NICs: %w", merr)
		}
		*changes = append(*changes, "remove_nics")
	}

	// nics[] = per-adapter tuning: {adapter, cable_connected?, promisc?,
	// speed?, boot_prio?, bandwidth_group?, nic_type?, mac?}.
	if tuning := listOr(metadata["nics"]); len(tuning) > 0 {
		e.taskProgress(task, 57, "tuning_nics")
		flags := []string{}
		for _, entry := range tuning {
			nic := mapOr(entry)
			adapter := int(intOr(nic["adapter"], 0))
			if adapter < 1 || adapter > maxNICSlots {
				return fmt.Errorf("nics entries need adapter 1-%d (got %v)", maxNICSlots, nic["adapter"])
			}
			n := strconv.Itoa(adapter)
			if mac := stringOr(nic["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
				flags = append(flags, "--mac-address"+n+"="+strings.ReplaceAll(mac, ":", ""))
			}
			flags = append(flags, nicExtraFlags(nic, n)...)
		}
		if len(flags) == 0 {
			return errors.New("nics entries carry no tunable keys")
		}
		if merr := vbox.ModifyVM(ctx, vboxExe, target, flags); merr != nil {
			return fmt.Errorf("failed to tune NICs: %w", merr)
		}
		*changes = append(*changes, "nics")
	}
	return nil
}

// modifyStorage handles the storage device model at modify:
// add_controllers/remove_controllers (storagectl — the multiple-adapters ask,
// Mark's go 2026-07-08), add_disks/remove_disks/add_cdroms/remove_cdroms.
// New media are created under the machine's working directory (the base's
// zfs create), existing media attach by path; entries address any controller
// by name (default "SATA Controller"); removals detach by controller port
// and PRESERVE the files (the base removes the zonecfg device, never the
// zvol).
func (e *executors) modifyStorage(ctx context.Context, task *tasks.Task, vboxExe, target, machineName string,
	info *vbox.Info, metadata map[string]any, changes *[]string, out *tasks.OutputWriter,
) error {
	if addControllers := listOr(metadata["add_controllers"]); len(addControllers) > 0 {
		e.taskProgress(task, 58, "adding_controllers")
		for _, entry := range addControllers {
			c := mapOr(entry)
			kind := storageControllerKind(stringOr(c["type"], ""))
			name := stringOr(c["name"], defaultControllerName(kind))
			bootable := true
			if v, ok := c["bootable"].(bool); ok {
				bootable = v
			}
			out.Write("stdout", fmt.Sprintf("Adding storage controller %q (%s)\n", name, kind))
			if cerr := vbox.AddStorageController(ctx, vboxExe, target, name, kind,
				int(intOr(c["ports"], 0)), bootable); cerr != nil {
				return fmt.Errorf("failed to add controller: %w", cerr)
			}
		}
		*changes = append(*changes, "add_controllers")
	}

	usedByController := map[string]map[int]bool{}
	usedOn := func(controller string) map[int]bool {
		if usedByController[controller] == nil {
			usedByController[controller] = usedPorts(info, controller)
		}
		return usedByController[controller]
	}

	if addDisks := listOr(metadata["add_disks"]); len(addDisks) > 0 {
		e.taskProgress(task, 60, "adding_disks")
		disksDir := filepath.Join(e.machineWorkdir(machineName), "disks")
		for _, entry := range addDisks {
			disk := mapOr(entry)
			controller := stringOr(disk["controller"], sataController)
			used := usedOn(controller)
			port := int(intOr(disk["port"], int64(nextFreePort(used, 1))))
			device := int(intOr(disk["device"], 0))
			path := stringOr(disk["path"], "")
			if path == "" {
				name := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", port))
				sizeMB := sizeToMB(disk["size"])
				if sizeMB <= 0 {
					sizeMB = 50 * 1024 // the base's 50G default
				}
				if merr := os.MkdirAll(disksDir, 0o750); merr != nil {
					return merr
				}
				path = filepath.Join(disksDir, name+".vdi")
				sparse := true
				if v, ok := disk["sparse"].(bool); ok {
					sparse = v
				}
				clearStaleMedium(ctx, vboxExe, path, out)
				out.Write("stdout", fmt.Sprintf("Creating %s (%d MB)\n", path, sizeMB))
				if cerr := vbox.CreateMedium(ctx, vboxExe, path, sizeMB, sparse); cerr != nil {
					return fmt.Errorf("failed to create disk volume: %w", cerr)
				}
			}
			out.Write("stdout", fmt.Sprintf("Attaching %s at %s port %d device %d\n", path, controller, port, device))
			if aerr := vbox.StorageAttach(ctx, vboxExe, target, controller, port, device, "hdd", path); aerr != nil {
				return fmt.Errorf("failed to add disk: %w", aerr)
			}
			used[port] = true
		}
		*changes = append(*changes, "add_disks")
	}

	if removeDisks := listOr(metadata["remove_disks"]); len(removeDisks) > 0 {
		e.taskProgress(task, 70, "removing_disks")
		if derr := e.detachPorts(ctx, vboxExe, target, removeDisks, "disk", usedOn, out); derr != nil {
			return derr
		}
		*changes = append(*changes, "remove_disks")
	}

	if addCdroms := listOr(metadata["add_cdroms"]); len(addCdroms) > 0 {
		e.taskProgress(task, 75, "adding_cdroms")
		for _, entry := range addCdroms {
			cdrom := mapOr(entry)
			iso, rerr := e.resolveCdromPath(ctx, cdrom)
			if rerr != nil {
				return rerr
			}
			if iso == "" {
				return errors.New("add_cdroms entries require a path or a cached-ISO iso name")
			}
			controller := stringOr(cdrom["controller"], sataController)
			used := usedOn(controller)
			port := int(intOr(cdrom["port"], int64(nextFreePort(used, 1))))
			device := int(intOr(cdrom["device"], 0))
			out.Write("stdout", fmt.Sprintf("Attaching %s at %s port %d device %d\n", iso, controller, port, device))
			if aerr := vbox.StorageAttach(ctx, vboxExe, target, controller, port, device, "dvddrive", iso); aerr != nil {
				return fmt.Errorf("failed to add CDROM: %w", aerr)
			}
			used[port] = true
		}
		*changes = append(*changes, "add_cdroms")
	}

	if removeCdroms := listOr(metadata["remove_cdroms"]); len(removeCdroms) > 0 {
		e.taskProgress(task, 80, "removing_cdroms")
		if derr := e.detachPorts(ctx, vboxExe, target, removeCdroms, "cdrom", usedOn, out); derr != nil {
			return derr
		}
		*changes = append(*changes, "remove_cdroms")
	}

	if removeControllers := listOr(metadata["remove_controllers"]); len(removeControllers) > 0 {
		e.taskProgress(task, 82, "removing_controllers")
		for _, entry := range removeControllers {
			name := stringOr(entry, "")
			if name == "" {
				return errors.New("remove_controllers entries name controllers (strings)")
			}
			out.Write("stdout", "Removing storage controller "+name+"\n")
			if cerr := vbox.RemoveStorageController(ctx, vboxExe, target, name); cerr != nil {
				return fmt.Errorf("failed to remove controller (detach its media first): %w", cerr)
			}
		}
		*changes = append(*changes, "remove_controllers")
	}
	return nil
}

// detachPorts detaches media (files preserved — the base's remove keeps the
// volume's data). Entries are bare port numbers (the "SATA Controller",
// device 0 — the original vocabulary) or {controller, port, device?} objects
// addressing any controller. "SATA Controller" port 0 is REFUSED: the base's
// diskN attrs never name the boot disk (bootdisk is its own attr), and on
// this agent that port carries the boot medium.
func (e *executors) detachPorts(ctx context.Context, vboxExe, target string,
	entries []any, kind string, usedOn func(string) map[int]bool, out *tasks.OutputWriter,
) error {
	for _, entry := range entries {
		controller := sataController
		device := 0
		port, ok := portNumber(entry)
		if !ok {
			object := mapOr(entry)
			if len(object) == 0 {
				return fmt.Errorf("remove_%ss entries are port numbers or {controller, port, device?} objects (got %v)", kind, entry)
			}
			controller = stringOr(object["controller"], sataController)
			port = int(intOr(object["port"], -1))
			device = int(intOr(object["device"], 0))
			if port < 0 {
				return fmt.Errorf("remove_%ss objects require a port (got %v)", kind, entry)
			}
		}
		if controller == sataController && port < 1 {
			return fmt.Errorf("remove_%ss: %q port 0 is the boot medium — ports 1 and up only (got %v)", kind, sataController, entry)
		}
		out.Write("stdout", fmt.Sprintf("Detaching %s port %d device %d (file preserved)\n", controller, port, device))
		if derr := vbox.StorageDetachDevice(ctx, vboxExe, target, controller, port, device); derr != nil {
			return fmt.Errorf("failed to remove %s: %w", kind, derr)
		}
		delete(usedOn(controller), port)
	}
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

// sataController is the storage controller create builds and modify extends.
const sataController = "SATA Controller"

// maxNICSlots is VirtualBox's adapter count on the default chipset.
const maxNICSlots = 8

// modifyAttributeFlags maps the base's attribute vocabulary onto modifyvm
// (ZoneAttributeModifier's attrMap, translated): ram/vcpus/os_type map
// directly; vnc drives VRDE; bootrom drives firmware; hostbridge drives the
// chipset; netif drives every configured adapter's hardware type; diskif has
// no modifyvm analog and is reported, never silently accepted.
func modifyAttributeFlags(metadata map[string]any, info *vbox.Info) (flags, notes []string, err error) {
	if v, ok := metadata["ram"]; ok {
		flags = append(flags, "--memory="+strconv.FormatInt(memoryToMB(v), 10))
	}
	if v, ok := metadata["vcpus"]; ok {
		// VCPUCount, not intOr (converged v2, sync 2026-07-17): a guard-passed
		// float-string like "4.0" must apply as 4, never the default.
		flags = append(flags, "--cpus="+strconv.FormatInt(VCPUCount(v, 2), 10))
	}
	if v, ok := metadata["os_type"]; ok {
		if s := stringOr(v, ""); s != "" {
			flags = append(flags, "--ostype="+s)
		}
	}
	if v, ok := metadata["vnc"]; ok {
		flags = append(flags, "--vrde="+onOff(v))
	}
	if v, ok := metadata["acpi"]; ok {
		flags = append(flags, "--acpi="+onOff(v))
	}
	if v, ok := metadata["xhci"]; ok {
		flags = append(flags, "--usb-xhci="+onOff(v))
	}
	if v, ok := metadata["bootrom"]; ok {
		firmware := "bios"
		if strings.Contains(strings.ToLower(stringOr(v, "")), "efi") {
			firmware = "efi"
		}
		flags = append(flags, "--firmware="+firmware)
	}
	if v, ok := metadata["hostbridge"]; ok {
		chipset := strings.ToLower(stringOr(v, ""))
		if chipset == "i440fx" {
			// bhyve's PIIX-era hostbridge is VirtualBox's PIIX3 chipset.
			chipset = "piix3"
		}
		if chipset != "" {
			flags = append(flags, "--chipset="+chipset)
		}
	}
	if v, ok := metadata["netif"]; ok {
		if nicType := vboxNICType(stringOr(v, "")); nicType == "" {
			notes = append(notes, "netif value "+stringOr(v, "")+" has no VirtualBox adapter type — skipped")
		} else {
			for n := 1; n <= maxNICSlots; n++ {
				if val, present := info.Raw["nic"+strconv.Itoa(n)]; present && val != "none" {
					flags = append(flags, "--nic-type"+strconv.Itoa(n)+"="+nicType)
				}
			}
		}
	}
	if _, ok := metadata["diskif"]; ok {
		notes = append(notes, "diskif selects the default controller's type at CREATE only — VirtualBox fixes a controller's type once media attach; add a NEW controller via add_controllers instead; skipped")
	}
	if v, ok := metadata["boot_order"]; ok {
		if bootFlags := bootOrderFlags(v); len(bootFlags) > 0 {
			flags = append(flags, bootFlags...)
		} else {
			notes = append(notes, "boot_order carries no usable entries (floppy|dvd|disk|net|none) — skipped")
		}
	}
	// hardware.<section>.<key> — the full knob vocabulary (hardware.go).
	if hardware := mapOr(metadata["hardware"]); len(hardware) > 0 {
		hwFlags, herr := hardwareFlags(hardware)
		if herr != nil {
			return nil, nil, herr
		}
		flags = append(flags, hwFlags...)
	}
	// The vbox.directives passthrough at MODIFY — the same generic modifyvm
	// attribute list create accepts (the zonecfg attr-map analog): any
	// --flag=value the Edit surface wants to reach.
	for _, entry := range listOr(mapOr(metadata["vbox"])["directives"]) {
		directive := mapOr(entry)
		if name := stringOr(directive["directive"], ""); name != "" {
			flags = append(flags, "--"+name+"="+stringOr(directive["value"], ""))
		}
	}
	return flags, notes, nil
}

// vboxNICType maps the document's netif vocabulary onto VirtualBox adapter
// hardware types ("" when there is no analog).
func vboxNICType(netif string) string {
	switch strings.ToLower(netif) {
	case "virtio":
		return "virtio"
	case "e1000":
		return "82540EM"
	}
	return ""
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

// freeNICSlots lists the adapters showvminfo reports as none (or absent).
func freeNICSlots(info *vbox.Info) []int {
	free := []int{}
	for n := 1; n <= maxNICSlots; n++ {
		if value, ok := info.Raw["nic"+strconv.Itoa(n)]; !ok || value == "none" {
			free = append(free, n)
		}
	}
	return free
}

// usedPorts reads a controller's occupied ports from the live view — the
// machinereadable attachment keys are "<Controller>-<port>-<device>"; any
// occupied device marks the port used (next-free-port picks a wholly free
// port; explicit port+device entries can still target IDE's second device).
func usedPorts(info *vbox.Info, controller string) map[int]bool {
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(controller) + `-(\d+)-(\d+)$`)
	used := map[int]bool{}
	for key, value := range info.Raw {
		match := pattern.FindStringSubmatch(key)
		if match == nil || value == "none" {
			continue
		}
		if port, err := strconv.Atoi(match[1]); err == nil {
			used[port] = true
		}
	}
	return used
}

// nextFreePort finds the first unoccupied port at or above from.
func nextFreePort(used map[int]bool, from int) int {
	port := from
	for used[port] {
		port++
	}
	return port
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
