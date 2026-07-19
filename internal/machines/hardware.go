package machines

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// hardware.<section>.<key> → modifyvm flags — the full 7.2 knob surface
// (Mark's ALL-knobs ruling 2026-07-09). Values pass through unvalidated
// (VirtualBox's own errors); unknown sections/keys are hard errors. Not
// first-class (vbox.directives reaches them): teleporter, cpuid-set,
// tracing/testing, guest-debug, pci-attach, plug/unplug-cpu, --name.

// hardwareValue tells how a document value becomes the flag's argument.
type hardwareValue int

const (
	hwOnOff  hardwareValue = iota // bool / "on"/"true"/1 → on|off
	hwString                      // verbatim — VirtualBox validates enums
	hwInt                         // integer
)

// hardwareKnob is one modifyvm flag behind a document key.
type hardwareKnob struct {
	flag string
	kind hardwareValue
}

// hardwareVocabulary maps hardware.<section>.<key> onto modifyvm flags —
// the 7.2 usage dump, complete (Mark's host, 2026-07-09).
var hardwareVocabulary = map[string]map[string]hardwareKnob{
	"cpu": {
		"hotplug":                 {"cpu-hotplug", hwOnOff},
		"execution_cap":           {"cpu-execution-cap", hwInt},
		"profile":                 {"cpu-profile", hwString},
		"pae":                     {"x86-pae", hwOnOff},
		"long_mode":               {"x86-long-mode", hwOnOff},
		"hwvirtex":                {"hwvirtex", hwOnOff},
		"nested_paging":           {"nested-paging", hwOnOff},
		"large_pages":             {"large-pages", hwOnOff},
		"nested_hw_virt":          {"nested-hw-virt", hwOnOff},
		"virt_vmsave_vmload":      {"virt-vmsave-vmload", hwOnOff},
		"vtx_vpid":                {"x86-vtx-vpid", hwOnOff},
		"vtx_ux":                  {"x86-vtx-ux", hwOnOff},
		"apic":                    {"apic", hwOnOff},
		"x2apic":                  {"x86-x2apic", hwOnOff},
		"hpet":                    {"x86-hpet", hwOnOff},
		"spec_ctrl":               {"spec-ctrl", hwOnOff},
		"ibpb_on_vm_exit":         {"ibpb-on-vm-exit", hwOnOff},
		"ibpb_on_vm_entry":        {"ibpb-on-vm-entry", hwOnOff},
		"l1d_flush_on_sched":      {"l1d-flush-on-sched", hwOnOff},
		"l1d_flush_on_vm_entry":   {"l1d-flush-on-vm-entry", hwOnOff},
		"mds_clear_on_sched":      {"mds-clear-on-sched", hwOnOff},
		"mds_clear_on_vm_entry":   {"mds-clear-on-vm-entry", hwOnOff},
		"arm_gic_its":             {"arm-gic-its", hwOnOff},
		"cpuid_portability_level": {"cpuid-portability-level", hwInt},
	},
	"memory": {
		"vram":        {"vram", hwInt},
		"page_fusion": {"page-fusion", hwOnOff},
		"balloon":     {"guest-memory-balloon", hwInt},
	},
	"graphics": {
		"controller":    {"graphicscontroller", hwString},
		"monitor_count": {"monitor-count", hwInt},
		"accelerate_3d": {"accelerate-3d", hwOnOff},
	},
	"audio": {
		"enabled":    {"audio-enabled", hwOnOff},
		"driver":     {"audio-driver", hwString},
		"controller": {"audio-controller", hwString},
		"codec":      {"audio-codec", hwString},
		"in":         {"audio-in", hwOnOff},
		"out":        {"audio-out", hwOnOff},
	},
	"usb": {
		"ohci":        {"usb-ohci", hwOnOff},
		"ehci":        {"usb-ehci", hwOnOff},
		"xhci":        {"usb-xhci", hwOnOff},
		"card_reader": {"usb-card-reader", hwOnOff},
	},
	"integration": {
		"clipboard_mode":           {"clipboard-mode", hwString},
		"clipboard_file_transfers": {"clipboard-file-transfers", hwString},
		"drag_and_drop":            {"drag-and-drop", hwString},
		"mouse":                    {"mouse", hwString},
		"keyboard":                 {"keyboard", hwString},
	},
	"platform": {
		"chipset":             {"chipset", hwString},
		"iommu":               {"iommu", hwString},
		"tpm_type":            {"tpm-type", hwString},
		"tpm_location":        {"tpm-location", hwString},
		"rtc_use_utc":         {"rtc-use-utc", hwOnOff},
		"paravirt_provider":   {"paravirt-provider", hwString},
		"ioapic":              {"ioapic", hwOnOff},
		"triple_fault_reset":  {"triple-fault-reset", hwOnOff},
		"hardware_uuid":       {"hardware-uuid", hwString},
		"system_uuid_le":      {"system-uuid-le", hwOnOff},
		"snapshot_folder":     {"snapshot-folder", hwString},
		"description":         {"description", hwString},
		"groups":              {"groups", hwString},
		"icon_file":           {"icon-file", hwString},
		"default_frontend":    {"default-frontend", hwString},
		"vm_process_priority": {"vm-process-priority", hwString},
		"vm_execution_engine": {"vm-execution-engine", hwString},
	},
	"firmware": {
		"boot_menu":          {"firmware-boot-menu", hwString},
		"apic":               {"firmware-apic", hwString},
		"logo_fade_in":       {"firmware-logo-fade-in", hwOnOff},
		"logo_fade_out":      {"firmware-logo-fade-out", hwOnOff},
		"logo_display_time":  {"firmware-logo-display-time", hwInt},
		"logo_image_path":    {"firmware-logo-image-path", hwString},
		"system_time_offset": {"firmware-system-time-offset", hwInt},
		"pxe_debug":          {"firmware-pxe-debug", hwOnOff},
	},
	"recording": {
		"enabled":          {"recording", hwOnOff},
		"screens":          {"recording-screens", hwString},
		"file":             {"recording-file", hwString},
		"max_size_mb":      {"recording-max-size", hwInt},
		"max_time_seconds": {"recording-max-time", hwInt},
		"opts":             {"recording-opts", hwString},
		"video_fps":        {"recording-video-fps", hwInt},
		"video_rate":       {"recording-video-rate", hwInt},
		"video_res":        {"recording-video-res", hwString},
	},
	"vrde": {
		"enabled":               {"vrde", hwOnOff},
		"port":                  {"vrde-port", hwString}, // ranges: "5000,5010-5012"
		"extpack":               {"vrde-extpack", hwString},
		"address":               {"vrde-address", hwString},
		"auth_type":             {"vrde-auth-type", hwString},
		"auth_library":          {"vrde-auth-library", hwString},
		"multi_con":             {"vrde-multi-con", hwOnOff},
		"reuse_con":             {"vrde-reuse-con", hwOnOff},
		"video_channel":         {"vrde-video-channel", hwOnOff},
		"video_channel_quality": {"vrde-video-channel-quality", hwInt},
	},
	"autostart": {
		"enabled": {"autostart-enabled", hwOnOff},
		"delay":   {"autostart-delay", hwInt},
	},
}

// hardwareEnumValues carries the closed vocabularies of the hwString knobs
// (the VBoxManage 7.2.8 usage dump) — KnobValues' source alongside the
// on|off knobs. Free-form string knobs (paths, names, ranges) are absent.
var hardwareEnumValues = map[string]map[string][]string{
	"cpu": {
		"profile": {"host", "Intel 8086", "Intel 80286", "Intel 80386"},
	},
	"graphics": {
		"controller": {"none", "vboxvga", "vmsvga", "vboxsvga", "qemuramfb"},
	},
	"audio": {
		"driver":     {"none", "default", "null", "dsound", "was", "oss", "alsa", "pulse", "coreaudio"},
		"controller": {"ac97", "hda", "sb16"},
		"codec":      {"stac9700", "ad1980", "stac9221", "sb16"},
	},
	"integration": {
		"clipboard_mode":           {"disabled", "hosttoguest", "guesttohost", "bidirectional"},
		"clipboard_file_transfers": {"enabled", "disabled"},
		"drag_and_drop":            {"disabled", "hosttoguest", "guesttohost", "bidirectional"},
		"mouse":                    {"none", "ps2", "usb", "usbtablet", "usbmultitouch", "usbmtscreenpluspad"},
		"keyboard":                 {"none", "ps2", "usb"},
	},
	"platform": {
		"chipset":             {"piix3", "ich9", "armv8virtual"},
		"iommu":               {"none", "automatic", "amd", "intel"},
		"tpm_type":            {"none", "1.2", "2.0", "host", "swtpm"},
		"paravirt_provider":   {"none", "default", "legacy", "minimal", "hyperv", "kvm"},
		"vm_process_priority": {"default", "flat", "low", "normal", "high"},
		"vm_execution_engine": {"default", "hm", "hwvirt", "nem", "native-api", "interpreter", "recompiler"},
	},
	"firmware": {
		"boot_menu": {"disabled", "menuonly", "messageandmenu"},
		"apic":      {"disabled", "apic", "x2apic"},
	},
	"vrde": {
		"auth_type": {"null", "external", "guest"},
	},
}

// KnobValues publishes the machine-readable value vocabularies of every
// closed-vocabulary knob (GET /machines/defaults knob_values — the UI's
// dropdown feed, Mark's enum ruling 2026-07-09). Keys are FLAT DOTTED, one
// wire shape with zoneweaver (the 2026-07-12 one-wire ruling): literal
// hardware.<section>.<key> derived from the modifyvm vocabulary (on|off knobs
// + the usage dump's enums), plus the document-level zones.<key>, nics.<key>,
// disks.controller_type, boot_order (entry values), settings.sync_method.
// Free-form and numeric knobs are absent — presence in the map MEANS dropdown.
func KnobValues() map[string][]string {
	values := map[string][]string{
		"hardware.serial.type":  {"16450", "16550A", "16750"},
		"zones.bootrom":         {"bios", "efi"},
		"zones.hostbridge":      {"i440fx", "piix3", "ich9", "armv8virtual"},
		"zones.vnc":             {"on", "off"},
		"zones.acpi":            {"on", "off"},
		"zones.xhci":            {"on", "off"},
		"zones.netif":           {"virtio", "e1000"},
		"zones.diskif":          {"ide", "sata", "scsi", "sas", "nvme", "virtio", "usb", "floppy"},
		"nics.promisc":          {"deny", "allow-vms", "allow-all"},
		"nics.nic_type":         {"Am79C970A", "Am79C973", "82540EM", "82543GC", "82545EM", "virtio", "usbnet"},
		"nics.cable_connected":  {"on", "off"},
		"disks.controller_type": {"ide", "sata", "scsi", "sas", "nvme", "virtio", "usb", "floppy"},
		"boot_order":            {"floppy", "dvd", "disk", "net", "none"},
		"settings.sync_method":  {"rsync", "scp"},
	}
	for sectionName, section := range hardwareVocabulary {
		for key, knob := range section {
			if knob.kind == hwOnOff {
				values["hardware."+sectionName+"."+key] = []string{"on", "off"}
				continue
			}
			if enum, ok := hardwareEnumValues[sectionName][key]; ok {
				values["hardware."+sectionName+"."+key] = enum
			}
		}
	}
	return values
}

// MachineKnobDefaults publishes the value an UNSET knob effectively runs with
// (GET /machines/defaults knob_defaults — the companion to knob_current the UI
// AI asked for 2026-07-12: knob_current shows what is SET, knob_defaults shows
// what an unset knob runs with, so a blank Edit field can read the effective
// value instead of "(agent default)"). FLAT DOTTED, one wire shape with
// zoneweaver, values in PUT's vocabulary and knob_current's own value types
// (int for ram/vcpus/boot_priority, on|off strings for the toggles).
//
// SOURCED FROM THE CREATE PATH, NEVER GUESSED (Mark's don't-invent rule, the
// same discipline that made zoneweaver read the brand boot program): every
// entry is a value the AGENT deterministically sets regardless of guest OS
// type — modifyFlags' forced console baseline, the vcpus/memory fallbacks, and
// the agent-policy settings defaults. VirtualBox's OS-TYPE RECOMMENDATIONS
// (bootrom, hostbridge, netif, vram, chipset, audio controller/codec, the
// firmware and mitigation families…) are DELIBERATELY OMITTED: they vary by
// guest OS type and are not knowable statically without inventing — knob_current
// serves each machine's real value live from its .vbox (absence = default,
// filled as a real value), and the create-time labels read machineCreateDefaults
// (the zones/settings sections). An omitted key keeps the UI's "(default)"
// label, exactly as zoneweaver omits bootorder/memreserve.
func MachineKnobDefaults() map[string]any {
	defaults := map[string]any{}

	// Resource fallbacks (modifyFlags: --cpus default 2, --memory default 2048 MB).
	defaults["vcpus"] = 2
	defaults["ram"] = 2048

	// The forced console baseline modifyFlags emits on EVERY create (Mark's
	// browser-RDP-era directive 2026-07-10) — an unset field runs with these.
	// Keys mirror knob_current's own positions (top-level xhci + its
	// hardware.usb twin, hardware.integration.*, hardware.vrde.*).
	defaults["xhci"] = "on"
	defaults["hardware.usb.xhci"] = "on"
	defaults["hardware.integration.mouse"] = "usbtablet"
	defaults["hardware.integration.keyboard"] = "usb"
	defaults["hardware.integration.clipboard_mode"] = "bidirectional"
	defaults["hardware.integration.clipboard_file_transfers"] = "enabled"
	defaults["hardware.vrde.multi_con"] = "on"
	defaults["hardware.vrde.reuse_con"] = "on"

	// Agent-policy defaults: storageControllerKind's default bus, the
	// orchestration boot priority an unset machine runs at, the sync transport
	// an unset spec renders with.
	defaults["diskif"] = "sata"
	defaults["boot_priority"] = 95
	defaults["settings.sync_method"] = "rsync"

	// The remove-on-completion default feed (the converged flip wire, sync
	// 2026-07-18 — UI's Q3: knob_defaults['transport.remove_on_completion']):
	// the value an ABSENT flag runs with on THIS agent — Mark's per-agent
	// ruling: Go keeps the transport (false, the home/dev model); zoneweaver
	// serves true (the datacenter model).
	defaults["transport.remove_on_completion"] = false

	// VirtualBox constructor defaults already encoded in this agent's own
	// settings-file reader, plus the spelled disk defaults (UI defaults ask,
	// sync 2026-07-18).
	defaults["nics.cable_connected"] = "on"
	defaults["nics.promisc"] = "deny"
	defaults["nics.speed"] = 0
	defaults["nics.boot_prio"] = 0
	defaults["disks.controller_type"] = "sata"
	defaults["disks.sparse"] = true
	defaults["disks.volume_name"] = "boot | disk<N>"
	defaults["disks.directory"] = "machine folder"

	return defaults
}

// hardwareFlags translates a hardware section into modifyvm arguments:
// sorted k=v knobs, then serial[]/parallel[] multi-arg sequences.
func hardwareFlags(hardware map[string]any) ([]string, error) {
	kv := []string{}
	sequences := []string{}
	for sectionName, raw := range hardware {
		switch sectionName {
		case "serial":
			serial, err := serialFlags(listOr(raw))
			if err != nil {
				return nil, err
			}
			sequences = append(sequences, serial...)
			continue
		case "parallel":
			parallel, err := parallelFlags(listOr(raw))
			if err != nil {
				return nil, err
			}
			sequences = append(sequences, parallel...)
			continue
		}
		vocabulary, known := hardwareVocabulary[sectionName]
		if !known {
			return nil, fmt.Errorf("hardware.%s is not a known section", sectionName)
		}
		section, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("hardware.%s must be an object", sectionName)
		}
		for key, value := range section {
			knob, kok := vocabulary[key]
			if !kok {
				return nil, fmt.Errorf("hardware.%s.%s is not a known knob", sectionName, key)
			}
			switch knob.kind {
			case hwOnOff:
				kv = append(kv, "--"+knob.flag+"="+onOff(value))
			case hwInt:
				kv = append(kv, "--"+knob.flag+"="+strconv.FormatInt(intOr(value, 0), 10))
			default:
				kv = append(kv, "--"+knob.flag+"="+stringOr(value, ""))
			}
		}
	}
	sort.Strings(kv)
	return append(kv, sequences...), nil
}

// serialFlags emits hardware.serial[] entries ({port, io_base, irq, mode,
// type}); --uartN/--uart-modeN take separate argv words.
func serialFlags(entries []any) ([]string, error) {
	flags := []string{}
	for _, raw := range entries {
		entry := mapOr(raw)
		port := int(intOr(entry["port"], 0))
		if port < 1 || port > 4 {
			return nil, fmt.Errorf("hardware.serial entries need port 1-4 (got %v)", entry["port"])
		}
		n := strconv.Itoa(port)
		ioBase := stringOr(entry["io_base"], "")
		switch {
		case ioBase == "" || strings.EqualFold(ioBase, "off"):
			flags = append(flags, "--uart"+n+"=off")
		default:
			irq := intOr(entry["irq"], -1)
			if irq < 0 {
				return nil, fmt.Errorf("hardware.serial port %d needs irq alongside io_base", port)
			}
			flags = append(flags, "--uart"+n, ioBase, strconv.FormatInt(irq, 10))
		}
		if mode := stringOr(entry["mode"], ""); mode != "" {
			// Every mode kind takes at most ONE argument after the kind word
			// (server/client/file paths, tcpserver port, tcpclient host:port),
			// so split once — a pipe path with spaces stays whole.
			flags = append(flags, "--uart-mode"+n)
			flags = append(flags, strings.SplitN(mode, " ", 2)...)
		}
		if uartType := stringOr(entry["type"], ""); uartType != "" {
			flags = append(flags, "--uart-type"+n+"="+uartType)
		}
	}
	return flags, nil
}

// serialPortClaimed reports whether hardware.serial[] addresses the given
// port — the guest-agent UART's collision rule: the document wins.
func serialPortClaimed(hardware map[string]any, port int) bool {
	for _, raw := range listOr(hardware["serial"]) {
		if int(intOr(mapOr(raw)["port"], 0)) == port {
			return true
		}
	}
	return false
}

// parallelFlags emits hardware.parallel[] entries ({port, io_base, irq,
// device}).
func parallelFlags(entries []any) ([]string, error) {
	flags := []string{}
	for _, raw := range entries {
		entry := mapOr(raw)
		port := int(intOr(entry["port"], 0))
		if port < 1 || port > 2 {
			return nil, fmt.Errorf("hardware.parallel entries need port 1-2 (got %v)", entry["port"])
		}
		n := strconv.Itoa(port)
		ioBase := stringOr(entry["io_base"], "")
		switch {
		case ioBase == "" || strings.EqualFold(ioBase, "off"):
			flags = append(flags, "--lpt"+n+"=off")
		default:
			irq := intOr(entry["irq"], -1)
			if irq < 0 {
				return nil, fmt.Errorf("hardware.parallel port %d needs irq alongside io_base", port)
			}
			flags = append(flags, "--lpt"+n, ioBase, strconv.FormatInt(irq, 10))
		}
		if device := stringOr(entry["device"], ""); device != "" {
			flags = append(flags, "--lpt-mode"+n+"="+device)
		}
	}
	return flags, nil
}

// nicExtraFlags emits per-adapter tuning (cable_connected, promisc, speed,
// boot_prio, bandwidth_group, raw nic_type) onto adapter n.
func nicExtraFlags(network map[string]any, n string) []string {
	flags := []string{}
	if value, ok := network["cable_connected"]; ok {
		flags = append(flags, "--cable-connected"+n+"="+onOff(value))
	}
	if promisc := stringOr(network["promisc"], ""); promisc != "" {
		flags = append(flags, "--nic-promisc"+n+"="+promisc)
	}
	if value, ok := network["speed"]; ok {
		flags = append(flags, "--nic-speed"+n+"="+strconv.FormatInt(intOr(value, 0), 10))
	}
	if value, ok := network["boot_prio"]; ok {
		flags = append(flags, "--nic-boot-prio"+n+"="+strconv.FormatInt(intOr(value, 0), 10))
	}
	if group := stringOr(network["bandwidth_group"], ""); group != "" {
		flags = append(flags, "--nic-bandwidth-group"+n+"="+group)
	}
	if nicType := stringOr(network["nic_type"], ""); nicType != "" {
		flags = append(flags, "--nic-type"+n+"="+nicType)
	}
	return flags
}
