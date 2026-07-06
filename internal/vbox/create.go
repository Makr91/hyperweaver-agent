package vbox

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Machine-creation verbs — zoneweaver's zonecfg/zfs storage+config operations
// spoken in VBoxManage (Mark's ruling: same mechanism, hypervisor-native
// tools). Each maps one base operation: template clone → clonemedium, volume
// grow → modifymedium --resize, zonecfg create/attrs → createvm + modifyvm,
// device add → storagectl + storageattach, cloud-init attrs → guestproperty.

// CloneMedium copies a disk image to a new path (the template import — both
// of the base's clone strategies land here: VirtualBox media have no
// cross-VM thin clone, so clone and copy are one operation). Operand order
// per the 7.2 CLI: source, target, then the medium type.
func CloneMedium(ctx context.Context, vboxManage, source, target, format string) error {
	args := []string{"clonemedium", source, target, "disk"}
	if format != "" {
		args = append(args, "--format="+format)
	}
	return runSimple(ctx, vboxManage, args...)
}

// ResizeMedium grows a disk image to sizeMB (the base's volsize grow —
// shrinking is refused by VirtualBox, exactly like the base warns rather
// than shrinks).
func ResizeMedium(ctx context.Context, vboxManage, path string, sizeMB int64) error {
	return runSimple(ctx, vboxManage, "modifymedium", "disk", path,
		"--resize="+strconv.FormatInt(sizeMB, 10))
}

// CreateMedium creates a blank disk image (the scratch boot volume;
// dynamic = sparse).
func CreateMedium(ctx context.Context, vboxManage, path string, sizeMB int64, sparse bool) error {
	variant := "Standard"
	if !sparse {
		variant = "Fixed"
	}
	return runSimple(ctx, vboxManage, "createmedium", "disk",
		"--filename="+path, "--size="+strconv.FormatInt(sizeMB, 10), "--variant="+variant)
}

// CloseMedium releases a disk image from the media registry, optionally
// deleting it (the storage rollback's zfs destroy).
func CloseMedium(ctx context.Context, vboxManage, path string, deleteFile bool) error {
	args := []string{"closemedium", "disk", path}
	if deleteFile {
		args = append(args, "--delete")
	}
	return runSimple(ctx, vboxManage, args...)
}

// CreateVM registers a new machine (zonecfg create): basefolder is the
// machines root — VirtualBox creates <basefolder>/<name>/ itself. The 7.2
// CLI REQUIRES --platform-architecture (x86 | arm); the caller maps the
// document's box_arch (amd64 → x86, arm64 → arm).
func CreateVM(ctx context.Context, vboxManage, name, platformArch, osType, baseFolder string) (string, error) {
	if platformArch == "" {
		platformArch = "x86"
	}
	args := []string{
		"createvm", "--name=" + name,
		"--platform-architecture=" + platformArch, "--register",
	}
	if osType != "" {
		args = append(args, "--ostype="+osType)
	}
	if baseFolder != "" {
		args = append(args, "--basefolder="+baseFolder)
	}
	cmd := exec.CommandContext(ctx, vboxManage, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		return "", fmt.Errorf("VBoxManage createvm %s: %w: %s", name, err, detail)
	}
	// Output carries `UUID: <uuid>` — the identity the row records.
	for _, line := range strings.Split(string(out), "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "UUID:"); found {
			return strings.TrimSpace(value), nil
		}
	}
	return "", nil
}

// ModifyVM applies machine settings (the zonecfg attribute batch): flags are
// raw `--key value` pairs assembled by the caller from the document.
func ModifyVM(ctx context.Context, vboxManage, name string, flags []string) error {
	return runSimple(ctx, vboxManage, append([]string{"modifyvm", name}, flags...)...)
}

// AddStorageController attaches a named controller (the device bus the
// bootdisk/additional disks/cdroms hang off).
func AddStorageController(ctx context.Context, vboxManage, name, controller, kind string) error {
	return runSimple(ctx, vboxManage, "storagectl", name,
		"--name="+controller, "--add="+kind, "--bootable=on")
}

// StorageAttach attaches one medium (disk image or ISO) to a controller port
// (the base's add device / add fs blocks).
func StorageAttach(ctx context.Context, vboxManage, name, controller string, port int, kind, medium string) error {
	return runSimple(ctx, vboxManage, "storageattach", name,
		"--storagectl="+controller,
		"--port="+strconv.Itoa(port), "--device=0",
		"--type="+kind, "--medium="+medium)
}

// SetGuestProperty records one key/value on the machine (the cloud-init
// attribute transport — guest tooling reads these where zones read zonecfg
// attrs).
func SetGuestProperty(ctx context.Context, vboxManage, name, key, value string) error {
	return runSimple(ctx, vboxManage, "guestproperty", "set", name, key, value)
}

// GuestProperty reads one guest property value ("" when unset) — the
// post-boot view (IP discovery and friends).
func GuestProperty(ctx context.Context, vboxManage, name, key string) (string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "guestproperty", "get", name, key)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("VBoxManage guestproperty get: %w", err)
	}
	value := strings.TrimSpace(string(out))
	if value == "No value set!" {
		return "", nil
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Value:")), nil
}
