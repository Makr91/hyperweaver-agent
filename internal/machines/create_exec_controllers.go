package machines

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// storageControllerKind maps the document's controller-type vocabulary onto
// storagectl --add types (yardstick 2: the controller type is the user's
// choice at create; VirtualBox fixes a controller's type once media attach).
// Default sata. The full storagectl bus set is exposed — Mark's rule: every
// option VirtualBox has.
func storageControllerKind(diskif string) string {
	switch strings.ToLower(diskif) {
	case "ide":
		return "ide"
	case "scsi":
		return "scsi"
	case "sas":
		return "sas"
	case "nvme", "pcie":
		return "pcie"
	case "virtio", "virtio-scsi", "virtio-blk":
		return "virtio"
	case "usb":
		return "usb"
	case "floppy":
		return "floppy"
	default:
		return "sata"
	}
}

// controllerPlan is one storage controller the create builds, with its
// next-free-port counter for entries that declare no port.
type controllerPlan struct {
	name     string
	kind     string
	ports    int
	bootable bool
	nextPort int
}

// storageControllers derives the create's controller set — the device model
// (Mark's Proxmox/VirtualBox correction 2026-07-07 + the multiple-adapters
// ask 2026-07-08): disks.controllers[] entries ({name?, type, ports?,
// bootable?}) each become a storagectl controller; media then address them by
// name. Absent, ONE default controller exists exactly as before — type from
// zones.diskif, the stable "SATA Controller" label modify addresses ports
// through (the name deliberately survives a non-SATA diskif for port-address
// stability).
func storageControllers(document MachineConfig) ([]*controllerPlan, error) {
	plans := []*controllerPlan{}
	seen := map[string]bool{}
	for _, entry := range listOr(document.Section("disks")["controllers"]) {
		c := mapOr(entry)
		if len(c) == 0 {
			continue
		}
		kind := storageControllerKind(stringOr(c["type"], ""))
		name := stringOr(c["name"], defaultControllerName(kind))
		if seen[name] {
			return nil, fmt.Errorf("disks.controllers: duplicate controller name %q", name)
		}
		seen[name] = true
		bootable := true
		if v, ok := c["bootable"].(bool); ok {
			bootable = v
		}
		plans = append(plans, &controllerPlan{
			name:     name,
			kind:     kind,
			ports:    int(intOr(c["ports"], 0)),
			bootable: bootable,
		})
	}
	if len(plans) == 0 {
		plans = append(plans, &controllerPlan{
			name:     sataController,
			kind:     "sata",
			bootable: true,
		})
	}
	return plans, nil
}

// defaultControllerName names an unnamed controller after its bus.
func defaultControllerName(kind string) string {
	switch kind {
	case "ide":
		return "IDE Controller"
	case "scsi":
		return "SCSI Controller"
	case "sas":
		return "SAS Controller"
	case "pcie":
		return "NVMe Controller"
	case "virtio":
		return "VirtIO Controller"
	case "usb":
		return "USB Controller"
	case "floppy":
		return "Floppy Controller"
	default:
		return sataController
	}
}

// resolveController picks an entry's controller: its own controller name when
// declared (must exist), else the first (default) controller.
func resolveController(plans []*controllerPlan, entry map[string]any) (*controllerPlan, error) {
	name := stringOr(entry["controller"], "")
	if name == "" {
		return plans[0], nil
	}
	for _, plan := range plans {
		if plan.name == name {
			return plan, nil
		}
	}
	return nil, fmt.Errorf("controller %q is not declared in disks.controllers", name)
}

// attachStorage wires the media over the controller set: boot at the default
// controller's port 0 (or its own controller/port/device), additional disks
// and cdroms at their declared controller/port/device or the controller's
// next free port.
func (e *executors) attachStorage(ctx context.Context, vboxExe, name string,
	document MachineConfig, output *createExecutionOutput, out *tasks.OutputWriter,
) error {
	plans, err := storageControllers(document)
	if err != nil {
		return err
	}
	for _, plan := range plans {
		if plan.kind != "sata" || plan.name != sataController || plan.ports > 0 {
			out.Write("stdout", fmt.Sprintf("Storage controller %q (%s)\n", plan.name, plan.kind))
		}
		if cerr := vbox.AddStorageController(ctx, vboxExe, name, plan.name, plan.kind, plan.ports, plan.bootable); cerr != nil {
			return cerr
		}
	}

	disks := document.Section("disks")
	// Diskless machines (the base's prepareBootVolume null) have no boot
	// medium — the controllers still exist so modify can attach media later.
	if output.BootdiskPath != "" {
		boot := mapOr(disks["boot"])
		plan, berr := resolveController(plans, boot)
		if berr != nil {
			return berr
		}
		port := int(intOr(boot["port"], 0))
		device := int(intOr(boot["device"], 0))
		if aerr := vbox.StorageAttach(ctx, vboxExe, name, plan.name, port, device, "hdd", output.BootdiskPath); aerr != nil {
			return aerr
		}
		if output.BootdiskMultiattach {
			if serr := e.stampDifferencingChild(ctx, vboxExe, name, output.BootdiskPath, out); serr != nil {
				return serr
			}
		}
		if port >= plan.nextPort {
			plan.nextPort = port + 1
		}
	}

	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		if len(disk) == 0 {
			continue
		}
		diskName := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
		path := stringOr(disk["path"], "")
		if path == "" {
			// The created file's location honors the entry's directory (the
			// addendum) exactly as createStorage placed it — the two MUST
			// agree or the attach misses the medium.
			targetDir, derr := diskDirectory(disk,
				filepath.Join(e.machineWorkdir(name), "disks"),
				"disks.additional_disks["+strconv.Itoa(i+1)+"]")
			if derr != nil {
				return derr
			}
			path = filepath.Join(targetDir, diskName+".vdi")
		}
		plan, perr := resolveController(plans, disk)
		if perr != nil {
			return perr
		}
		port := int(intOr(disk["port"], int64(plan.nextPort)))
		device := int(intOr(disk["device"], 0))
		out.Write("stdout", fmt.Sprintf("Attaching %s at %s port %d device %d\n", path, plan.name, port, device))
		if aerr := vbox.StorageAttach(ctx, vboxExe, name, plan.name, port, device, "hdd", path); aerr != nil {
			return aerr
		}
		if port >= plan.nextPort {
			plan.nextPort = port + 1
		}
	}

	for _, entry := range listOr(disks["cdroms"]) {
		cdrom := mapOr(entry)
		iso, rerr := e.resolveCdromPath(ctx, cdrom)
		if rerr != nil {
			return rerr
		}
		if iso == "" {
			continue
		}
		plan, perr := resolveController(plans, cdrom)
		if perr != nil {
			return perr
		}
		port := int(intOr(cdrom["port"], int64(plan.nextPort)))
		device := int(intOr(cdrom["device"], 0))
		out.Write("stdout", fmt.Sprintf("Attaching %s at %s port %d device %d\n", iso, plan.name, port, device))
		if aerr := vbox.StorageAttach(ctx, vboxExe, name, plan.name, port, device, "dvddrive", iso); aerr != nil {
			return aerr
		}
		if port >= plan.nextPort {
			plan.nextPort = port + 1
		}
	}
	return nil
}

// resolveCdromPath answers a cdroms[] entry's medium: path verbatim (raw
// paths stay legal), or iso — a cached-ISO filename resolved through the
// artifact registry (Mark's ruling 2026-07-09).
func (e *executors) resolveCdromPath(ctx context.Context, cdrom map[string]any) (string, error) {
	if path := stringOr(cdrom["path"], ""); path != "" {
		return path, nil
	}
	name := stringOr(cdrom["iso"], "")
	if name == "" {
		return "", nil
	}
	if e.env.Assets == nil {
		return "", errors.New("cdroms[].iso references the artifact registry — artifact_storage.enabled is false")
	}
	artifact, err := e.env.Assets.FindByKindFilename(ctx, assets.KindISO, name)
	if errors.Is(err, assets.ErrNotFound) {
		return "", fmt.Errorf("ISO %q is not in any storage location — upload or download it first (GET /artifacts/iso lists what exists)", name)
	}
	if err != nil {
		return "", err
	}
	return artifact.Path, nil
}
