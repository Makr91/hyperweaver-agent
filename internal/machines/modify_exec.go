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

	attrFlags, notes := modifyAttributeFlags(metadata, info)
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

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+machine.Name+" modified successfully ("+
		strings.Join(changes, ", ")+"). Changes take effect on next start.\n")
	return nil
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
	return nil
}

// modifyStorage handles add_disks/remove_disks/add_cdroms/remove_cdroms
// (handleStorageModifications): new media are created under the machine's
// working directory (the base's zfs create), existing media attach by path;
// removals detach by SATA port and PRESERVE the files (the base removes the
// zonecfg device, never the zvol).
func (e *executors) modifyStorage(ctx context.Context, task *tasks.Task, vboxExe, target, machineName string,
	info *vbox.Info, metadata map[string]any, changes *[]string, out *tasks.OutputWriter,
) error {
	used := usedSATAPorts(info)

	if addDisks := listOr(metadata["add_disks"]); len(addDisks) > 0 {
		e.taskProgress(task, 60, "adding_disks")
		disksDir := filepath.Join(e.machineWorkdir(machineName), "disks")
		for _, entry := range addDisks {
			disk := mapOr(entry)
			port := nextFreePort(used, 1)
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
			out.Write("stdout", fmt.Sprintf("Attaching %s at port %d\n", path, port))
			if aerr := vbox.StorageAttach(ctx, vboxExe, target, sataController, port, "hdd", path); aerr != nil {
				return fmt.Errorf("failed to add disk: %w", aerr)
			}
			used[port] = true
		}
		*changes = append(*changes, "add_disks")
	}

	if removeDisks := listOr(metadata["remove_disks"]); len(removeDisks) > 0 {
		e.taskProgress(task, 70, "removing_disks")
		if derr := e.detachPorts(ctx, vboxExe, target, removeDisks, "disk", used, out); derr != nil {
			return derr
		}
		*changes = append(*changes, "remove_disks")
	}

	if addCdroms := listOr(metadata["add_cdroms"]); len(addCdroms) > 0 {
		e.taskProgress(task, 75, "adding_cdroms")
		for _, entry := range addCdroms {
			iso := stringOr(mapOr(entry)["path"], "")
			if iso == "" {
				return errors.New("add_cdroms entries require a path")
			}
			port := nextFreePort(used, 1)
			out.Write("stdout", fmt.Sprintf("Attaching %s at port %d\n", iso, port))
			if aerr := vbox.StorageAttach(ctx, vboxExe, target, sataController, port, "dvddrive", iso); aerr != nil {
				return fmt.Errorf("failed to add CDROM: %w", aerr)
			}
			used[port] = true
		}
		*changes = append(*changes, "add_cdroms")
	}

	if removeCdroms := listOr(metadata["remove_cdroms"]); len(removeCdroms) > 0 {
		e.taskProgress(task, 80, "removing_cdroms")
		if derr := e.detachPorts(ctx, vboxExe, target, removeCdroms, "cdrom", used, out); derr != nil {
			return derr
		}
		*changes = append(*changes, "remove_cdroms")
	}
	return nil
}

// detachPorts detaches media by SATA port number (files preserved — the
// base's remove keeps the volume's data). Port 0 is REFUSED: the base's
// diskN attrs never name the boot disk (bootdisk is its own attr), and on
// this agent port 0 IS the boot medium — a base-vocabulary "disk0" must
// never detach it, so only explicit ports 1+ are accepted.
func (e *executors) detachPorts(ctx context.Context, vboxExe, target string,
	entries []any, kind string, used map[int]bool, out *tasks.OutputWriter,
) error {
	for _, entry := range entries {
		port, ok := portNumber(entry)
		if !ok || port < 1 {
			return fmt.Errorf("remove_%ss entries name SATA port numbers 1 and up — port 0 is the boot medium (got %v)", kind, entry)
		}
		out.Write("stdout", fmt.Sprintf("Detaching port %d (file preserved)\n", port))
		if derr := vbox.StorageDetach(ctx, vboxExe, target, sataController, port); derr != nil {
			return fmt.Errorf("failed to remove %s: %w", kind, derr)
		}
		delete(used, port)
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
func modifyAttributeFlags(metadata map[string]any, info *vbox.Info) (flags, notes []string) {
	if v, ok := metadata["ram"]; ok {
		flags = append(flags, "--memory="+strconv.FormatInt(memoryToMB(v), 10))
	}
	if v, ok := metadata["vcpus"]; ok {
		flags = append(flags, "--cpus="+strconv.FormatInt(intOr(v, 2), 10))
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
		notes = append(notes, "diskif has no VirtualBox modifyvm analog (the controller type is fixed at attach) — skipped")
	}
	return flags, notes
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

// sataPortPattern matches the machinereadable storage-attachment keys
// ("SATA Controller-<port>-0").
var sataPortPattern = regexp.MustCompile(`^` + sataController + `-(\d+)-0$`)

// usedSATAPorts reads the occupied controller ports from the live view.
func usedSATAPorts(info *vbox.Info) map[int]bool {
	used := map[int]bool{}
	for key, value := range info.Raw {
		match := sataPortPattern.FindStringSubmatch(key)
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
