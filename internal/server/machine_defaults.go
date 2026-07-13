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
		"vcpus":         2,
		"memory":        "2048M",
		"os_type":       "Debian_64",
		"box_arch":      "amd64",
		"box_version":   "latest",
		"boot_priority": 95,
		"sync_method":   "rsync",
	},
	"zones": map[string]any{
		"bootrom":     "bios",
		"hostbridge":  "piix3",
		"vnc":         "off",
		"acpi":        "on",
		"xhci":        "off",
		"netif":       "e1000",
		"diskif":      "sata",
		"autostart":   false,
		"guest_agent": false,
	},
	"disks": map[string]any{
		"sparse":     true,
		"controller": "SATA Controller",
	},
	// knob_values: every closed-vocabulary knob's allowed values (the UI's
	// dropdown feed — Mark's enum ruling 2026-07-09). Presence MEANS dropdown;
	// free-form/numeric knobs are absent.
	"knob_values": machines.KnobValues(),
	"notes": map[string]any{
		"sync_method": "Platform rules apply on top: forced rsync on Windows hosts; macOS auto-falls back to scp when the system rsync is the ancient Apple build.",
		"zones":       "bootrom/hostbridge/vnc/acpi/xhci/netif are VirtualBox's own defaults — the agent passes no flag when the field is omitted. guest_agent (boolean, default false) opts the machine into the QEMU guest-agent UART (per-machine, under the guest_agent.enabled master gate — the Proxmox model, shared with zoneweaver).",
		"settings":    "vcpus/memory/os_type are this agent's fallbacks, applied when the field is omitted.",
		"disks":       "Omitting disks.controllers[] creates one controller named \"SATA Controller\" of zones.diskif's type; media default onto it, sparse, at the next free port.",
		"knob_values": "Value vocabularies for enum knobs. Keys are FLAT DOTTED strings, never nested objects — knob_values[\"hardware.<section>.<key>\"], [\"zones.<key>\"], [\"nics.<key>\"], [\"disks.controller_type\"], [\"boot_order\"] (entry values), [\"settings.sync_method\"]; each value is a string array. A knob present here is a dropdown; a knob absent is free-form or numeric. Values pass to VirtualBox unvalidated — unknown values stay legal (VirtualBox answers).",
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
