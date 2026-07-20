package machines

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Remove-on-completion — the converged cross-agent flag (sync 2026-07-18;
// MARK'S EXECUTION RULING): when the user selected transport removal, the
// PIPELINE owns the power cycle — after the whole-walk stamp the chain runs
// stop → machine_transport_remove → start, and the post-removal boot gates on
// NOTHING (the transport is gone by design; the machine comes up on its real
// NICs, possibly unreachable from the agent — that is the point). Two flag
// homes, one semantic: configuration.settings.remove_transport_on_completion
// targets the INTRINSIC NAT transport (adapter 1 — it has no document entry,
// so the per-entry key can never express it; the wizard's per-create signal
// lands here), and networks[] entries' per-entry remove_on_completion targets
// their own adapters (i+2). Absent flags = this agent's ruled default FALSE
// (keep — the home/dev model; zoneweaver defaults true, the datacenter model).

// OpTransportRemove is the removal task operation.
const OpTransportRemove = "machine_transport_remove"

// TransportRemovalFlagged reports whether ANYTHING is flagged for removal —
// the chain builder's gate (reads the flags LIVE from the stored document, so
// a flip between queue and run is honored by the executor's own re-read).
func TransportRemovalFlagged(config MachineConfig) bool {
	settings := config.Section("settings")
	if flag, ok := settings["remove_transport_on_completion"].(bool); ok && flag {
		return true
	}
	for _, entry := range config.List("networks") {
		if flag, _ := mapOr(entry)["remove_on_completion"].(bool); flag {
			return true
		}
	}
	return false
}

// transportRemove executes machine_transport_remove: against the POWERED-OFF
// machine (the chained stop precedes), remove every flagged adapter — the
// intrinsic NAT (its natpf forwards deleted first; --nic1=none) when the
// settings flag says so, and each flagged networks[] entry's adapter — then
// update the DOCUMENT to match reality (entries removed, is_control flipped
// to the first surviving entry, the settings flag cleared — document
// honesty). Flags are re-read from the stored document at RUN time.
func (e *executors) transportRemove(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	target := machine.VBoxTarget()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, target)
	if err != nil {
		return err
	}
	switch MapVBoxState(info.State) {
	case StatusStopped, StatusAborted:
	default:
		return fmt.Errorf("machine is %s — transport removal needs the powered-off machine the chained stop leaves", info.State)
	}

	config := ParseConfiguration(machine)
	settings := config.Section("settings")
	removeTransport, _ := settings["remove_transport_on_completion"].(bool)
	flagged := []int{}
	hostFlagged := []int{}
	for i, entry := range config.List("networks") {
		network := mapOr(entry)
		if flag, _ := network["remove_on_completion"].(bool); !flag {
			continue
		}
		flagged = append(flagged, i)
		if stringOr(network["type"], "") == "host" {
			hostFlagged = append(hostFlagged, i)
		}
	}
	if !removeTransport && len(flagged) == 0 {
		out.Write("stdout", "Nothing is flagged remove_on_completion anymore — no adapters removed\n")
		return nil
	}

	e.taskProgress(task, 20, "removing_adapters")
	flags := []string{}
	if removeTransport {
		if info.Raw["nic1"] == "nat" {
			// The NAT engine's named forwards die explicitly — they live in the
			// stored config and would return if the adapter were ever re-enabled.
			for key, value := range info.Raw {
				if !strings.HasPrefix(key, "Forwarding(") {
					continue
				}
				name := strings.SplitN(value, ",", 2)[0]
				out.Write("stdout", "Deleting NAT port-forward rule "+name+"\n")
				flags = append(flags, "--natpf1", "delete", name)
			}
			out.Write("stdout", "Removing the provisioning NAT transport (adapter 1) — the agent's SSH forward dies with it; later operations dial the machine's real NICs\n")
			flags = append(flags, "--nic1=none")
		} else {
			out.Write("stderr", "remove_transport_on_completion is set but adapter 1 is not the NAT transport (nic1="+
				info.Raw["nic1"]+") — nothing to remove there\n")
		}
	}
	for _, index := range flagged {
		adapter := strconv.Itoa(index + 2)
		out.Write("stdout", "Removing flagged adapter "+adapter+" (networks["+strconv.Itoa(index)+"])\n")
		flags = append(flags, "--nic"+adapter+"=none")
	}
	if len(flags) > 0 {
		if merr := vbox.ModifyVM(ctx, vboxExe, target, flags); merr != nil {
			return fmt.Errorf("adapter removal failed: %w", merr)
		}
	}

	// Fixed leases of flagged host-type entries — removed like delete does
	// (misses are silent; absent components never fail the removal).
	// hostonlynet (macOS) has no per-VM lease configs — nothing to remove.
	if e.env.Network.Enabled && len(hostFlagged) > 0 && !UseHostOnlyNets() {
		if iface, ferr := FindProvisioningIf(ctx, vboxExe, e.env.Network.HostIP); ferr == nil && iface != nil {
			for _, index := range hostFlagged {
				if rerr := vbox.RemoveDHCPVMConfig(ctx, vboxExe, iface.Name, target, index+2); rerr == nil {
					out.Write("stdout", fmt.Sprintf("Removed DHCP fixed lease for NIC %d\n", index+2))
				}
			}
		}
	}

	e.taskProgress(task, 70, "updating_document")
	if derr := e.applyTransportRemovalDocument(ctx, machine.Name, flagged, removeTransport, out); derr != nil {
		return derr
	}
	e.syncLiveConfiguration(ctx, machine.Name, vboxExe, target, out)
	e.refreshStatus(machine.Name, vboxExe)
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Transport removal complete — the chained boot brings the machine up on its real NICs\n")
	return nil
}

// applyTransportRemovalDocument updates the stored document after the
// adapters are gone (document honesty — the document mirrors reality): the
// flagged networks[] entries are REMOVED (surviving entries keep their raw
// bytes), is_control flips to the first surviving entry when a removed one
// carried it (that one entry re-encodes — narrated), and the settings flag
// clears (the intent is spent). One configuration write covers all of it.
func (e *executors) applyTransportRemovalDocument(ctx context.Context, machineName string,
	removedIndices []int, clearSettingsFlag bool, out *tasks.OutputWriter,
) error {
	machine, err := e.store.Get(ctx, machineName)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)

	if len(removedIndices) > 0 {
		if raw, ok := sections["networks"]; ok {
			rewritten, rerr := removeNetworkEntries(raw, removedIndices, out)
			if rerr != nil {
				return rerr
			}
			sections["networks"] = rewritten
		}
	}
	if clearSettingsFlag {
		settings := rawSectionMap(sections, "settings")
		delete(settings, "remove_transport_on_completion")
		raw, merr := json.Marshal(settings)
		if merr != nil {
			return merr
		}
		sections["settings"] = raw
		out.Write("stdout", "settings.remove_transport_on_completion cleared — the intent is spent\n")
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return e.store.SetConfiguration(ctx, machineName, merged)
}

// removeNetworkEntries drops the given indices from a raw networks array,
// surviving entries riding byte-verbatim. When a removed entry carried
// is_control, the FIRST surviving entry takes it (that entry alone
// re-encodes).
func removeNetworkEntries(raw json.RawMessage, removedIndices []int, out *tasks.OutputWriter) (json.RawMessage, error) {
	entries := []json.RawMessage{}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse stored networks for removal: %w", err)
	}
	removed := map[int]bool{}
	for _, index := range removedIndices {
		removed[index] = true
	}
	removedControl := false
	kept := []json.RawMessage{}
	for i, entry := range entries {
		if !removed[i] {
			kept = append(kept, entry)
			continue
		}
		var decoded map[string]any
		if uerr := json.Unmarshal(entry, &decoded); uerr == nil {
			if control, _ := decoded["is_control"].(bool); control {
				removedControl = true
			}
		}
	}
	if removedControl && len(kept) > 0 {
		var first map[string]any
		if uerr := json.Unmarshal(kept[0], &first); uerr == nil {
			first["is_control"] = true
			if rewritten, merr := json.Marshal(first); merr == nil {
				kept[0] = rewritten
				out.Write("stdout", "is_control flipped to the first surviving networks[] entry\n")
			}
		}
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, entry := range kept {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(entry)
	}
	buf.WriteByte(']')
	return json.RawMessage(buf.Bytes()), nil
}

// SetNetworkRemoveFlag flips networks[index].remove_on_completion in the
// stored document — the PUT flip wire (the converged cross-agent flag, sync
// 2026-07-18: a nics[] entry carrying {adapter, remove_on_completion} maps to
// the entry at adapter-2). Raw-preserving: only the touched entry re-encodes.
// An out-of-range index errors with the adapter named — the caller answers
// the 400.
func (s *Store) SetNetworkRemoveFlag(ctx context.Context, name string, index int, value bool) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	entries := []json.RawMessage{}
	if raw, ok := sections["networks"]; ok {
		if uerr := json.Unmarshal(raw, &entries); uerr != nil {
			return fmt.Errorf("parse stored networks: %w", uerr)
		}
	}
	if index < 0 || index >= len(entries) {
		return errors.New("adapter " + strconv.Itoa(index+2) +
			" has no document networks[] entry to carry remove_on_completion")
	}
	var entry map[string]any
	if uerr := json.Unmarshal(entries[index], &entry); uerr != nil {
		return fmt.Errorf("parse networks[%d]: %w", index, uerr)
	}
	entry["remove_on_completion"] = value
	rewritten, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	entries[index] = rewritten

	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(e)
	}
	buf.WriteByte(']')
	sections["networks"] = json.RawMessage(buf.Bytes())
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}
