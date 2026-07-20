package machines

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

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
		if verr := ValidateAddDisks(addDisks); verr != nil {
			return verr
		}
		disksDir := filepath.Join(e.machineWorkdir(machineName), "disks")
		for i, entry := range addDisks {
			disk := mapOr(entry)
			prefix := fmt.Sprintf("add_disks[%d]", i+1)
			controller := stringOr(disk["controller"], sataController)
			used := usedOn(controller)
			port := int(intOr(disk["port"], int64(nextFreePort(used, 1))))
			device := int(intOr(disk["device"], 0))
			var path string
			switch verbatimValue(disk["type"]) {
			case DiskTypeImage:
				path = stringOr(disk["path"], "")
				if _, serr := os.Stat(path); serr != nil {
					return errors.New(prefix + ".path " + path + " does not exist on this host")
				}
				if force, _ := disk["force"].(bool); force {
					out.Write("stdout", "force: true — skipping the in-use pre-check for "+path+"\n")
				} else {
					holder, herr := mediumHolder(ctx, vboxExe, path, machineName)
					if herr != nil {
						return herr
					}
					if holder != "" {
						return errors.New(prefix + ".path " + path + " is attached to " + holder +
							" (set force: true to attach anyway)")
					}
				}
				out.Write("stdout", "Attaching existing medium "+path+" (image — attached as-is, never ours to delete)\n")
			case DiskTypeBlank:
				name := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", port))
				targetDir, derr := diskDirectory(disk, disksDir, prefix)
				if derr != nil {
					return derr
				}
				if targetDir == disksDir {
					if merr := os.MkdirAll(disksDir, 0o750); merr != nil {
						return merr
					}
				}
				path = filepath.Join(targetDir, name+".vdi")
				sparse := true
				if v, ok := disk["sparse"].(bool); ok {
					sparse = v
				}
				clearStaleMedium(ctx, vboxExe, path, out)
				out.Write("stdout", fmt.Sprintf("Creating %s (%d MB)\n", path, sizeToMB(disk["size"])))
				if cerr := vbox.CreateMedium(ctx, vboxExe, path, sizeToMB(disk["size"]), sparse); cerr != nil {
					return fmt.Errorf("failed to create disk volume: %w", cerr)
				}
				if perr := stampMedium(ctx, vboxExe, path, DiskTypeBlank, out); perr != nil {
					return perr
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

// sataController is the storage controller create builds and modify extends.
const sataController = "SATA Controller"

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
