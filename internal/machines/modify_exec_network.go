package machines

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

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

	// nics[] = per-adapter tuning ({adapter, cable_connected?, promisc?,
	// speed?, boot_prio?, bandwidth_group?, nic_type?, mac?}) plus
	// RE-ATTACHMENT ({adapter, mode, network?} — the drag-to-rewire wire,
	// sync 2026-07-19).
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
			attachFlags, aerr := nicAttachmentFlags(nic, n)
			if aerr != nil {
				return aerr
			}
			flags = append(flags, attachFlags...)
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

// nicAttachmentFlags translates a nics[] entry's re-attachment pair (mode +
// network — the drag-to-rewire wire, sync 2026-07-19) into modifyvm flags.
// network is the mode's TARGET (bridged→host interface, hostonly→host-only
// ifname, hostonlynet/intnet/natnetwork→network name, generic→driver) and is
// required exactly where the mode addresses one; nat/none take no target.
// The hostonlynet spelling pair (mode word hostonlynet, flag --host-only-net)
// is usage-derived and unverified against a live hostonlynet machine.
func nicAttachmentFlags(nic map[string]any, n string) ([]string, error) {
	modeRaw, hasMode := nic["mode"]
	network := stringOr(nic["network"], "")
	if !hasMode {
		if network != "" {
			return nil, errors.New("nics[].network rides mode — send both to re-attach an adapter")
		}
		return nil, nil
	}
	mode := strings.ToLower(stringOr(modeRaw, ""))
	needTarget := func(flag string) ([]string, error) {
		if network == "" {
			return nil, fmt.Errorf("nics[].mode %s requires network (the attachment target)", mode)
		}
		return []string{"--nic" + n + "=" + mode, flag + n + "=" + network}, nil
	}
	switch mode {
	case "nat", "none", "null":
		if network != "" {
			return nil, fmt.Errorf("nics[].mode %s takes no network", mode)
		}
		return []string{"--nic" + n + "=" + mode}, nil
	case "bridged":
		return needTarget("--bridge-adapter")
	case "hostonly":
		return needTarget("--host-only-adapter")
	case "hostonlynet", "hostonlynetwork":
		if network == "" {
			return nil, errors.New("nics[].mode hostonlynet requires network (the attachment target)")
		}
		return []string{"--nic" + n + "=hostonlynet", "--host-only-net" + n + "=" + network}, nil
	case "intnet":
		return needTarget("--intnet")
	case "natnetwork":
		return needTarget("--nat-network")
	case "generic":
		return needTarget("--nic-generic-drv")
	}
	return nil, fmt.Errorf("nics[].mode %s is not a valid attachment mode (nat|bridged|hostonly|hostonlynet|intnet|natnetwork|generic|none)", mode)
}

// maxNICSlots is VirtualBox's adapter count on the default chipset.
const maxNICSlots = 8

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
