package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// GET /machines/defaults — the create-time defaults document (the UI AI's
// create-defaults ask, Mark's go 2026-07-08): what a spec that OMITS each
// field actually gets, so the wizard can label "(default: bios)" instead of
// "(agent default)". Two default classes, both listed: values this agent
// applies itself (vcpus/memory/os_type — create_exec's fallbacks) and values
// that fall through to VirtualBox's own defaults because the agent passes no
// flag (chipset/acpi/xhci/nic type). Static by construction — update it when
// the create path's fallbacks change.
var machineCreateDefaults = map[string]any{
	"settings": map[string]any{
		"vcpus":                       2,
		"memory":                      "2048M",
		"os_type":                     "Debian_64",
		"box_arch":                    "amd64",
		"box_version":                 "latest",
		"boot_priority":               95,
		"sync_method":                 "rsync",
		"firmware_type":               "BIOS",
		"vagrant_ssh_insert_key":      false,
		"communicator":                "ssh",
		"winrm_port":                  5985,
		"winrm_transport":             "negotiate",
		"winrm_ssl_peer_verification": true,
	},
	"disks": map[string]any{
		"sparse":     true,
		"controller": "SATA Controller",
	},
	"vbox": map[string]any{
		"guest_agent":         false,
		"post_provision_boot": false,
	},
	// knob_values: every closed-vocabulary knob's allowed values (the UI's
	// dropdown feed — Mark's enum ruling 2026-07-09). Presence MEANS dropdown;
	// free-form/numeric knobs are absent.
	"knob_values": machines.KnobValues(),
	// knob_defaults: the value an UNSET knob effectively runs with (the UI AI's
	// ask 2026-07-12, companion to knob_current). Flat dotted, sourced from the
	// create path — never a guessed VirtualBox internal (see MachineKnobDefaults).
	"knob_defaults": machines.MachineKnobDefaults(),
	"notes": map[string]any{
		"sync_method":   "Platform rules apply on top: forced rsync on Windows hosts; macOS auto-falls back to scp when the system rsync is the ancient Apple build.",
		"settings":      "vcpus/memory/os_type are this agent's fallbacks, applied when the field is omitted. winrm_port's default becomes 5986 when winrm_transport is ssl and no explicit port is set. firmware_type is generic (both hypervisors consume it).",
		"vbox":          "VirtualBox's own per-hypervisor section (Mark's ruling, sync 2026-07-19 — zones is bhyve-only, utm reserved): the whole knob vocabulary lives at vbox.<section>.<key> (cpu, memory, graphics, audio, usb, integration, platform, firmware, recording, vrde, autostart, serial[], parallel[]) beside directives[]. guest_agent (boolean, default false) opts the machine into the QEMU guest-agent UART; post_provision_boot (boolean, default false) cycles the machine after a successful provision run.",
		"disks":         "Omitting disks.controllers[] creates one controller named \"SATA Controller\" of type sata; media default onto it, sparse, at the next free port.",
		"knob_values":   "Value vocabularies for enum knobs. Keys are FLAT DOTTED strings, never nested objects — knob_values[\"vbox.<section>.<key>\"], [\"nics.<key>\"], [\"disks.controller_type\"], [\"disks.boot.clone_strategy\"], [\"boot_order\"] (entry values), [\"settings.sync_method\"], [\"settings.firmware_type\"]; each value is a string array. A knob present here is a dropdown; a knob absent is free-form or numeric. Values pass to VirtualBox unvalidated — unknown values stay legal (VirtualBox answers).",
		"knob_defaults": "The value an UNSET knob effectively runs with (the companion to the detail GET's knob_current — current shows what is SET, this shows what a blank field runs with). Flat dotted, same key vocabulary as knob_values, values in knob_current's own types (int ram/vcpus/boot_priority, on|off strings). SOURCED FROM THE CREATE PATH, never a guessed VirtualBox internal: the agent's forced console baseline (xhci on, usbtablet mouse, usb keyboard, bidirectional clipboard, VRDE multi/reuse-con), the vcpus/memory fallbacks, and agent-policy defaults (diskif sata, boot_priority 95, sync_method rsync). VirtualBox's OS-type recommendations (bootrom/hostbridge/netif/vram/chipset/audio/firmware/mitigations) are DELIBERATELY ABSENT — they vary by guest OS type and knob_current serves each machine's real value live; the create-time labels for those read the zones/settings sections above. An absent key keeps the UI's own default label.",
	},
}

// handleMachineCreateDefaults serves the static defaults document.
func (s *Server) handleMachineCreateDefaults(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, machineCreateDefaults)
}

// handleMachineOSTypes serves VBoxManage's guest OS type vocabulary (GET
// /machines/ostypes) — the wizard's settings.os_type dropdown feed (Mark's
// go 2026-07-09). Live enumeration: whatever THIS VirtualBox build
// supports, never a baked-in list.
func (s *Server) handleMachineOSTypes(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	types, err := vbox.ListOSTypes(r.Context(), exe)
	if err != nil {
		slog.Error("list ostypes", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to enumerate guest OS types")
		return
	}
	writeJSON(w, map[string]any{"ostypes": types, "total": len(types)})
}
