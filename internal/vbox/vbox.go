// Package vbox shells out to VBoxManage for VirtualBox machine queries —
// the seed of the provisioning engine's hypervisor layer. Callers supply the
// VBoxManage path from the prerequisite detector, which has already
// validated it through safepath.
package vbox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// ErrNotFound reports that VirtualBox has no machine registered under the
// requested name or UUID.
var ErrNotFound = errors.New("machine not found in VirtualBox")

// vmLinePattern matches the `"VM name" {uuid}` lines VBoxManage list emits.
var vmLinePattern = regexp.MustCompile(`^"(?P<name>.+)" \{(?P<uuid>[0-9a-fA-F-]{36})\}$`)

// Registered is one `VBoxManage list vms` entry.
type Registered struct {
	Name string
	UUID string
}

// ListVMs returns the names of all registered VirtualBox machines.
func ListVMs(ctx context.Context, vboxManage string) ([]string, error) {
	regs, err := ListRegistered(ctx, vboxManage, "vms")
	if err != nil {
		return nil, err
	}
	return names(regs), nil
}

// ListRunningVMs returns the names of the currently running machines.
func ListRunningVMs(ctx context.Context, vboxManage string) ([]string, error) {
	regs, err := ListRegistered(ctx, vboxManage, "runningvms")
	if err != nil {
		return nil, err
	}
	return names(regs), nil
}

// ListRegistered returns name+UUID pairs for a list subset ("vms" or
// "runningvms").
func ListRegistered(ctx context.Context, vboxManage, subset string) ([]Registered, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", subset)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list %s: %w", subset, err)
	}

	regs := []Registered{}
	for _, line := range strings.Split(string(out), "\n") {
		if match := vmLinePattern.FindStringSubmatch(strings.TrimSpace(line)); match != nil {
			regs = append(regs, Registered{Name: match[1], UUID: match[2]})
		}
	}
	return regs, nil
}

func names(regs []Registered) []string {
	out := make([]string, 0, len(regs))
	for _, r := range regs {
		out = append(out, r.Name)
	}
	return out
}

// Info is one machine's `showvminfo --machinereadable` state — the
// authoritative live view (SHI rule: VirtualBox outranks vagrant's cache).
type Info struct {
	Name       string
	UUID       string
	State      string // running | poweroff | saved | paused | aborted | starting | stopping ...
	OSType     string
	ConfigFile string
	// Home is the directory holding the machine's .vbox file.
	Home     string
	MemoryMB int
	CPUs     int
	// Raw carries every machinereadable key — served as the machine's live
	// configuration document.
	Raw map[string]string
}

// machineReadableLine matches the machinereadable forms key="value",
// key=value, and "quoted key"="value" (storage attachment lines). Parens in
// the bare-key class carry the indexed families — Forwarding(0), natnet
// rules — which the transport resolution reads (runtime-proven 2026-07-07:
// without them every Forwarding line was silently dropped and the pipeline
// fell back to dialing the guest IP).
var machineReadableLine = regexp.MustCompile(`^(?:"([^"]+)"|([A-Za-z0-9_\-/()]+))=(?:"(.*)"|(.*))$`)

// ShowVMInfo fetches a machine's live state. ErrNotFound when VirtualBox no
// longer knows the machine.
func ShowVMInfo(ctx context.Context, vboxManage, nameOrUUID string) (*Info, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "showvminfo", nameOrUUID, "--machinereadable")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && strings.Contains(string(exitErr.Stderr), "Could not find a registered machine") {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("VBoxManage showvminfo %s: %w", nameOrUUID, err)
	}

	info := &Info{Raw: map[string]string{}}
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
		info.Raw[key] = value
		switch key {
		case "name":
			info.Name = value
		case "UUID":
			info.UUID = value
		case "VMState":
			info.State = value
		case "ostype":
			info.OSType = value
		case "CfgFile":
			info.ConfigFile = value
			info.Home = filepath.Dir(value)
		case "memory":
			if n, perr := strconv.Atoi(value); perr == nil {
				info.MemoryMB = n
			}
		case "cpus":
			if n, perr := strconv.Atoi(value); perr == nil {
				info.CPUs = n
			}
		}
	}
	return info, nil
}

// BridgedIf is one `list bridgedifs` block: the name plus the fields the
// picker filters on (Status/Wireless — macOS lists pseudo and down
// interfaces) and the darwin hostonlynet-backing exclusion matches by
// (IPAddress/NetworkMask).
type BridgedIf struct {
	Name        string
	IPAddress   string
	NetworkMask string
	Status      string
	Wireless    bool
}

// ListBridgedIfs parses `VBoxManage list bridgedifs` — Key: value blocks per
// interface (SHI's default-NIC detection, feeding the UI's bridge-interface
// picker).
func ListBridgedIfs(ctx context.Context, vboxManage string) ([]BridgedIf, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "bridgedifs")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list bridgedifs: %w", err)
	}
	interfaces := []BridgedIf{}
	var current *BridgedIf
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Name":
			interfaces = append(interfaces, BridgedIf{Name: value})
			current = &interfaces[len(interfaces)-1]
		case "IPAddress":
			if current != nil {
				current.IPAddress = value
			}
		case "NetworkMask":
			if current != nil {
				current.NetworkMask = value
			}
		case "Status":
			if current != nil {
				current.Status = value
			}
		case "Wireless":
			if current != nil {
				current.Wireless = strings.EqualFold(value, "Yes")
			}
		}
	}
	return interfaces, nil
}

// StartVM boots a machine (`startvm --type headless|gui`) — the direct path
// for machines that exist only in VirtualBox (design: dual-path management).
func StartVM(ctx context.Context, vboxManage, name string, gui bool) error {
	displayType := "headless"
	if gui {
		displayType = "gui"
	}
	return runSimple(ctx, vboxManage, "startvm", name, "--type", displayType)
}

// ControlVM drives a running machine: poweroff, acpipowerbutton, pause,
// resume, or savestate.
func ControlVM(ctx context.Context, vboxManage, name, action string) error {
	return runSimple(ctx, vboxManage, "controlvm", name, action)
}

// ControlVMArgs runs one controlvm verb with arguments — the runtime knobs
// beyond the bare power verbs (`vrdeproperty Security/Method=Negotiate`,
// `vrde on`, ...). The VRDP server queries Security/* properties per
// connection (VirtualBox-source-verified, runtime-proven on 7.2 2026-07-11),
// so VRDE TLS material set this way applies LIVE — no power cycle.
func ControlVMArgs(ctx context.Context, vboxManage, name string, args ...string) error {
	return runSimple(ctx, vboxManage, append([]string{"controlvm", name}, args...)...)
}

// UnregisterVM removes a machine from VirtualBox; deleteFiles also deletes
// its media and directories. VirtualBox itself refuses to delete media still
// attached to another machine — the shared-disk guard beyond that arrives
// with the disks subsystem.
func UnregisterVM(ctx context.Context, vboxManage, name string, deleteFiles bool) error {
	args := []string{"unregistervm", name}
	if deleteFiles {
		args = append(args, "--delete")
	}
	return runSimple(ctx, vboxManage, args...)
}

// runSimple executes a short-lived VBoxManage command, folding stderr into
// the returned error.
func runSimple(ctx context.Context, vboxManage string, args ...string) error {
	cmd := exec.CommandContext(ctx, vboxManage, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			return fmt.Errorf("VBoxManage %s: %w: %s", args[0], err, detail)
		}
		return fmt.Errorf("VBoxManage %s: %w", args[0], err)
	}
	return nil
}
