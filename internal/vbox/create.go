package vbox

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// runConfig runs a machine-configuration command, retrying VirtualBox's
// transient session-lock refusal: createvm/modifyvm release their write
// session ASYNCHRONOUSLY, so an immediately-following config command can
// catch "already locked for a session (or being unlocked)"
// (VBOX_E_INVALID_OBJECT_STATE — runtime-proven 2026-07-06; vagrant's own
// pacing hid this race).
func runConfig(ctx context.Context, vboxManage string, args ...string) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		err = runSimple(ctx, vboxManage, args...)
		if err == nil || !strings.Contains(err.Error(), "already locked for a session") {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(500 * time.Millisecond):
		}
	}
	return err
}

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
	return runConfig(ctx, vboxManage, append([]string{"modifyvm", name}, flags...)...)
}

// AddStorageController attaches a named controller (the device bus media
// hang off) — the full storagectl surface: kind is the bus type
// (ide|sata|scsi|sas|usb|pcie|virtio|floppy), ports overrides the
// controller's port count when > 0, bootable marks it BIOS-bootable.
func AddStorageController(ctx context.Context, vboxManage, name, controller, kind string, ports int, bootable bool) error {
	args := []string{"storagectl", name, "--name=" + controller, "--add=" + kind}
	if ports > 0 {
		args = append(args, "--portcount="+strconv.Itoa(ports))
	}
	if bootable {
		args = append(args, "--bootable=on")
	} else {
		args = append(args, "--bootable=off")
	}
	return runConfig(ctx, vboxManage, args...)
}

// RemoveStorageController deletes a named controller (storagectl --remove).
// VirtualBox refuses while media are attached — that error passes through
// honestly (detach first).
func RemoveStorageController(ctx context.Context, vboxManage, name, controller string) error {
	return runConfig(ctx, vboxManage, "storagectl", name,
		"--name="+controller, "--remove")
}

// StorageAttach attaches one medium (disk image or ISO) to a controller
// port+device (the base's add device / add fs blocks). device matters on IDE
// (two devices per port); every other bus uses device 0.
func StorageAttach(ctx context.Context, vboxManage, name, controller string, port, device int, kind, medium string) error {
	return runConfig(ctx, vboxManage, "storageattach", name,
		"--storagectl="+controller,
		"--port="+strconv.Itoa(port), "--device="+strconv.Itoa(device),
		"--type="+kind, "--medium="+medium)
}

// SetGuestProperty records one key/value on the machine (the cloud-init
// attribute transport — guest tooling reads these where zones read zonecfg
// attrs).
func SetGuestProperty(ctx context.Context, vboxManage, name, key, value string) error {
	return runConfig(ctx, vboxManage, "guestproperty", "set", name, key, value)
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
