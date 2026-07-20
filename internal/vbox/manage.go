package vbox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Machine-management verbs beyond create/lifecycle — the rest of the
// VBoxManage surface Mark's policy-free rule exposes: snapshots, whole-VM
// cloning (current-state copy), OVA export, and console screenshots. Each is
// a thin translation; all workflow opinion lives in the callers.

// Snapshot is one entry of a machine's snapshot tree
// (`snapshot <vm> list --machinereadable`).
type Snapshot struct {
	Name        string `json:"name"`
	UUID        string `json:"uuid"`
	Description string `json:"description,omitempty"`
	// Node is the machinereadable tree key ("SnapshotName", "SnapshotName-1",
	// "SnapshotName-1-1", ...) — the suffix encodes the tree position.
	Node string `json:"node"`
	// Current marks the snapshot the machine's state currently derives from.
	Current bool `json:"current"`
}

// ListSnapshots returns a machine's snapshot tree, empty when it has none
// (VBoxManage answers that case with a non-zero exit and a message rather
// than an empty list).
func ListSnapshots(ctx context.Context, vboxManage, name string) ([]Snapshot, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "snapshot", name, "list", "--machinereadable")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "does not have any snapshots") {
			return []Snapshot{}, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && strings.Contains(string(out), "Could not find a registered machine") {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("VBoxManage snapshot list: %w: %s", err, strings.TrimSpace(string(out)))
	}

	byNode := map[string]*Snapshot{}
	order := []string{}
	currentUUID := ""
	for _, line := range strings.Split(string(out), "\n") {
		match := machineReadableLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		key := match[1]
		if key == "" {
			key = match[2]
		}
		value := match[3]
		if value == "" {
			value = match[4]
		}
		switch {
		case key == "CurrentSnapshotUUID":
			currentUUID = value
		case strings.HasPrefix(key, "SnapshotName"):
			node := strings.TrimPrefix(key, "SnapshotName")
			byNode[node] = &Snapshot{Name: value, Node: "SnapshotName" + node}
			order = append(order, node)
		case strings.HasPrefix(key, "SnapshotUUID"):
			if s := byNode[strings.TrimPrefix(key, "SnapshotUUID")]; s != nil {
				s.UUID = value
			}
		case strings.HasPrefix(key, "SnapshotDescription"):
			if s := byNode[strings.TrimPrefix(key, "SnapshotDescription")]; s != nil {
				s.Description = value
			}
		}
	}
	list := make([]Snapshot, 0, len(order))
	for _, node := range order {
		s := byNode[node]
		s.Current = currentUUID != "" && s.UUID == currentUUID
		list = append(list, *s)
	}
	return list, nil
}

// TakeSnapshot records a snapshot. live avoids pausing a running machine
// (`--live`); running machines snapshot fine either way.
func TakeSnapshot(ctx context.Context, vboxManage, name, snapshot, description string, live bool) error {
	args := []string{"snapshot", name, "take", snapshot}
	if description != "" {
		args = append(args, "--description="+description)
	}
	if live {
		args = append(args, "--live")
	}
	return runSimple(ctx, vboxManage, args...)
}

// RestoreSnapshot reverts the machine to a snapshot's state (the machine must
// be powered off or saved — VirtualBox refuses otherwise).
func RestoreSnapshot(ctx context.Context, vboxManage, name, snapshot string) error {
	return runSimple(ctx, vboxManage, "snapshot", name, "restore", snapshot)
}

// DeleteSnapshot removes a snapshot, merging its state into its children.
func DeleteSnapshot(ctx context.Context, vboxManage, name, snapshot string) error {
	return runSimple(ctx, vboxManage, "snapshot", name, "delete", snapshot)
}

// SnapshotEdit renames a snapshot and/or rewrites its description
// (`VBoxManage snapshot <vm> edit`). Nil pointers omit the flag entirely;
// a non-nil empty description passes --description= to CLEAR the text
// (zoneweaver's description-empty-clears rule, converged 2026-07-17).
// Rename collisions and unknown snapshots surface as VBoxManage's own error.
func SnapshotEdit(ctx context.Context, vboxManage, name, snapshot string, newName, description *string) error {
	args := []string{"snapshot", name, "edit", snapshot}
	if newName != nil {
		args = append(args, "--name="+*newName)
	}
	if description != nil {
		args = append(args, "--description="+*description)
	}
	return runSimple(ctx, vboxManage, args...)
}

// CloneVM copies a whole machine — CURRENT state included, the piece
// clonemedium-from-template cannot give (VBoxManage clonevm). snapshot names
// a source snapshot to clone from (required for linked clones); linked makes
// a differencing clone against that snapshot instead of a full copy. MACs are
// reinitialized (VirtualBox's default policy) so source and clone never
// collide.
func CloneVM(ctx context.Context, vboxManage, source, newName, baseFolder, snapshot string, linked bool) error {
	args := []string{"clonevm", source, "--name=" + newName, "--register"}
	if baseFolder != "" {
		args = append(args, "--basefolder="+baseFolder)
	}
	if snapshot != "" {
		args = append(args, "--snapshot="+snapshot)
	}
	if linked {
		args = append(args, "--options=link")
	}
	return runSimple(ctx, vboxManage, args...)
}

// ExportVM writes a machine to an OVA/OVF appliance file (`VBoxManage
// export`) — the template-export building block and a portable backup.
func ExportVM(ctx context.Context, vboxManage, name, outputPath string) error {
	return runSimple(ctx, vboxManage, "export", name, "--output="+outputPath)
}

// StorageDetachDevice detaches the medium at an arbitrary controller, port,
// AND device (StorageDetach's port-0-device sibling — the delete safety sweep
// walks every attachment the live view reports). The file is preserved.
func StorageDetachDevice(ctx context.Context, vboxManage, name, controller string, port, device int) error {
	return runConfig(ctx, vboxManage, "storageattach", name,
		"--storagectl="+controller,
		fmt.Sprintf("--port=%d", port), fmt.Sprintf("--device=%d", device),
		"--medium=none")
}

// VNCExtpackUsable reports whether a usable VRDE module speaking VNC is
// installed (Mark's detection recipe 2026-07-06): `list extpacks` blocks must
// pair "VRDE Module: VBoxVNC" with "Usable: true" — the mere presence of a
// pack proves nothing (the Oracle pack reports an EMPTY VRDE Module).
func VNCExtpackUsable(ctx context.Context, vboxManage string) bool {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "extpacks")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	vncModule := false
	usable := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Pack no"):
			// A new pack block resets the pair.
			if vncModule && usable {
				return true
			}
			vncModule, usable = false, false
		case strings.HasPrefix(trimmed, "VRDE Module:"):
			vncModule = strings.Contains(trimmed, "VBoxVNC")
		case strings.HasPrefix(trimmed, "Usable:"):
			usable = strings.Contains(trimmed, "true")
		}
	}
	return vncModule && usable
}

// GuestPropertyEntry is one `guestproperty enumerate` line.
type GuestPropertyEntry struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Timestamp string `json:"timestamp,omitempty"`
	Flags     string `json:"flags,omitempty"`
}

// guestPropertyLine matches enumerate's output: `Name: <n>, value: <v>,
// timestamp: <t>, flags: <f>` (older builds print `/path` without the Name:
// prefix variant; both forms carry the comma-separated fields).
var guestPropertyLine = regexp.MustCompile(`^Name: (.*), value: (.*), timestamp: (\d+), flags: ?(.*)$`)

// EnumerateGuestProperties lists every guest property on a machine — the
// post-boot view (guest-additions IPs, OS info, this agent's cloud-init
// keys). ErrNotFound when VirtualBox no longer knows the machine.
func EnumerateGuestProperties(ctx context.Context, vboxManage, name string) ([]GuestPropertyEntry, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "guestproperty", "enumerate", name)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "Could not find a registered machine") {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("VBoxManage guestproperty enumerate: %w: %s",
			err, strings.TrimSpace(string(out)))
	}
	entries := []GuestPropertyEntry{}
	for _, line := range strings.Split(string(out), "\n") {
		match := guestPropertyLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		entries = append(entries, GuestPropertyEntry{
			Name:      match[1],
			Value:     match[2],
			Timestamp: match[3],
			Flags:     strings.TrimSpace(match[4]),
		})
	}
	return entries, nil
}

// Screenshot captures the running machine's framebuffer to a PNG file
// (`controlvm screenshotpng`) — no console session needed.
func Screenshot(ctx context.Context, vboxManage, name, pngPath string) error {
	return runSimple(ctx, vboxManage, "controlvm", name, "screenshotpng", pngPath)
}

// InjectNMI injects a non-maskable interrupt into a running machine
// (`debugvm injectnmi`) — the diagnostic trigger for guest crash dumps and
// kernel debuggers; zoneweaver's `bhyvectl --inject-nmi` analog.
func InjectNMI(ctx context.Context, vboxManage, name string) error {
	return runSimple(ctx, vboxManage, "debugvm", name, "injectnmi")
}

// ControlVMNatPF hot-adds one adapter-1 NAT port-forward rule on a RUNNING
// machine (`controlvm <vm> natpf1 "name,proto,hostip,hostport,guestip,
// guestport"`) — takes effect immediately, persists into the stored config.
func ControlVMNatPF(ctx context.Context, vboxManage, name, rule string) error {
	return runSimple(ctx, vboxManage, "controlvm", name, "natpf1", rule)
}

// ControlVMNatPFDelete removes one adapter-1 forward rule by name from a
// RUNNING machine.
func ControlVMNatPFDelete(ctx context.Context, vboxManage, name, ruleName string) error {
	return runSimple(ctx, vboxManage, "controlvm", name, "natpf1", "delete", ruleName)
}

// SharedFolderAdd registers a shared folder on a machine (`sharedfolder add`
// — works on running machines too; VirtualBox hot-adds through the session).
// automount + an auto-mount-point let Guest Additions mount it without any
// guest command.
func SharedFolderAdd(ctx context.Context, vboxManage, name, shareName, hostPath, autoMountPoint string) error {
	args := []string{
		"sharedfolder", "add", name,
		"--name=" + shareName, "--hostpath=" + hostPath, "--automount",
	}
	if autoMountPoint != "" {
		args = append(args, "--auto-mount-point="+autoMountPoint)
	}
	return runConfig(ctx, vboxManage, args...)
}

// ImportAppliance imports an OVA/OVF into VirtualBox (`import --vsys 0`) —
// export's missing pair. vmName and baseFolder override the appliance's own
// suggestions when set.
func ImportAppliance(ctx context.Context, vboxManage, path, vmName, baseFolder string) error {
	args := []string{"import", path, "--vsys", "0"}
	if vmName != "" {
		args = append(args, "--vmname", vmName)
	}
	if baseFolder != "" {
		args = append(args, "--basefolder", baseFolder)
	}
	return runSimple(ctx, vboxManage, args...)
}

// MoveVM relocates a machine's VirtualBox files (`movevm --type basic`) —
// the .vbox, snapshots, and every medium stored with the machine land under
// folder. Powered-off machines only (VirtualBox refuses otherwise).
func MoveVM(ctx context.Context, vboxManage, name, folder string) error {
	return runSimple(ctx, vboxManage, "movevm", name, "--type", "basic", "--folder", folder)
}

// SetVideoModeHint asks the guest to resize its display
// (`controlvm setvideomodehint`) — honored by guests running Guest Additions.
func SetVideoModeHint(ctx context.Context, vboxManage, name string, width, height, depth, display int) error {
	args := []string{
		"controlvm", name, "setvideomodehint",
		strconv.Itoa(width), strconv.Itoa(height), strconv.Itoa(depth),
	}
	if display > 0 {
		args = append(args, strconv.Itoa(display))
	}
	return runSimple(ctx, vboxManage, args...)
}

// SetMediumProperty sets one custom key/value on a disk medium
// (`modifymedium disk <path> --property key=value`) — the provenance stamp's
// write half (typed disk spec, converged sync 2026-07-17).
func SetMediumProperty(ctx context.Context, vboxManage, path, key, value string) error {
	return runSimple(ctx, vboxManage, "modifymedium", "disk", path,
		"--property", key+"="+value)
}

// SetMediumType changes a medium's type (`modifymedium disk <path> --type`).
func SetMediumType(ctx context.Context, vboxManage, path, mediumType string) error {
	return runSimple(ctx, vboxManage, "modifymedium", "disk", path,
		"--type", mediumType)
}

// MediumType reads a medium's type from `showmediuminfo disk <path>`.
func MediumType(ctx context.Context, vboxManage, path string) (string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "showmediuminfo", "disk", path)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("VBoxManage showmediuminfo: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, found := strings.CutPrefix(strings.TrimSpace(line), "Type:"); found {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return strings.ToLower(fields[0]), nil
			}
		}
	}
	return "", nil
}

// GetMediumProperty reads one custom medium property back. Mechanism:
// `showmediuminfo disk <path>` — its "Property: key=value" lines are the only
// CLI read for medium properties (modifymedium sets, never gets). "" when the
// key is unset; a missing/unregistered medium answers the command's error.
func GetMediumProperty(ctx context.Context, vboxManage, path, key string) (string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "showmediuminfo", "disk", path)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("VBoxManage showmediuminfo: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), "Property:")
		if !found {
			continue
		}
		name, value, ok := strings.Cut(strings.TrimSpace(rest), "=")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value), nil
		}
	}
	return "", nil
}

// HDD is one `VBoxManage list hdds --long` block — the media inventory the
// delete flow's stamp rule, the image attach pre-check, and GET /media read.
type HDD struct {
	// UUID is VirtualBox's registry identity for the medium — the
	// registry-hygiene close targets it (closing a stale entry by PATH
	// re-opens the file and dies on the very UUID mismatch being cleaned).
	// Never on the /media wire (the frozen shape carries no uuid).
	UUID string `json:"-"`
	// ParentUUID links a differencing child to its base ("" for base media).
	ParentUUID string   `json:"-"`
	Path       string   `json:"path"`
	Format     string   `json:"format"`
	SizeBytes  int64    `json:"size_bytes"`
	InUseBy    []string `json:"in_use_by"`
}

// hddInUseVM matches the VM references the "In use by VMs:" lines carry —
// `<name> (UUID: <uuid>)`, with an optional snapshot suffix after the UUID
// (non-greedy name so the FIRST UUID parenthesis terminates the match).
var hddInUseVM = regexp.MustCompile(`^(.+?) \(UUID: [0-9a-fA-F-]{36}\)`)

// ListHDDs inventories every registered disk medium (`list hdds --long` —
// the short listing omits the attachment lines): Location, Storage format,
// Capacity (MBytes → bytes), and the VM names holding the medium. Blocks are
// blank-line separated and each opens with its UUID line.
func ListHDDs(ctx context.Context, vboxManage string) ([]HDD, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "hdds", "--long")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list hdds: %w", err)
	}

	hdds := []HDD{}
	var current *HDD
	flush := func() {
		if current != nil {
			hdds = append(hdds, *current)
			current = nil
		}
	}
	inUseBlock := false
	for _, raw := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			flush()
			inUseBlock = false
			continue
		}
		// A new block's opening UUID line ("Parent UUID:" deliberately does
		// not match — it never opens a block).
		if strings.HasPrefix(trimmed, "UUID:") {
			flush()
			current = &HDD{UUID: strings.TrimSpace(strings.TrimPrefix(trimmed, "UUID:"))}
			inUseBlock = false
			continue
		}
		if current == nil {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "Parent UUID:"):
			parent := strings.TrimSpace(strings.TrimPrefix(trimmed, "Parent UUID:"))
			if !strings.EqualFold(parent, "base") {
				current.ParentUUID = parent
			}
			inUseBlock = false
		case strings.HasPrefix(trimmed, "Location:"):
			current.Path = strings.TrimSpace(strings.TrimPrefix(trimmed, "Location:"))
			inUseBlock = false
		case strings.HasPrefix(trimmed, "Storage format:"):
			current.Format = strings.TrimSpace(strings.TrimPrefix(trimmed, "Storage format:"))
			inUseBlock = false
		case strings.HasPrefix(trimmed, "Capacity:"):
			fields := strings.Fields(strings.TrimPrefix(trimmed, "Capacity:"))
			if len(fields) > 0 {
				if mb, perr := strconv.ParseInt(fields[0], 10, 64); perr == nil {
					current.SizeBytes = mb * 1024 * 1024
				}
			}
			inUseBlock = false
		case strings.HasPrefix(trimmed, "In use by VMs:"):
			inUseBlock = true
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "In use by VMs:"))
			if match := hddInUseVM.FindStringSubmatch(rest); match != nil {
				current.InUseBy = append(current.InUseBy, match[1])
			}
		case inUseBlock:
			// Continuation lines list further holders, indented.
			if match := hddInUseVM.FindStringSubmatch(trimmed); match != nil {
				current.InUseBy = append(current.InUseBy, match[1])
			} else {
				inUseBlock = false
			}
		}
	}
	flush()
	return hdds, nil
}
