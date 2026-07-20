package machines

import (
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The showvminfo→PUT reverse map — hardware.go's forward map read backwards,
// built key-by-key from the machinereadable EMITTER (VBoxManageInfo.cpp,
// VirtualBox 7.2.8 source; Mark's method ruling 2026-07-09: the emitting code
// is the vocabulary, a dump is only a validation sample). Knobs the emitter
// never prints are OMITTED as unknowable: audio controller/codec, TPM,
// per-NIC promisc/boot_prio/bandwidth_group (human-readable branch only),
// recording screens/max_size/max_time, vrde extpack/auth_library, cpu
// hotplug + the mitigation family (spec_ctrl/ibpb/l1d/mds), usb card_reader,
// firmware logo family + pxe_debug, platform tpm/system_uuid_le/icon_file/
// vm_execution_engine.

// KnobCurrent presents a machine's CURRENT values in PUT /machines/{name}'s
// exact vocabulary (GET /machines/{name} knob_current — the Edit-surface
// prefill): top-level zones-vocabulary fields, hardware.<section>.<key>,
// hardware.serial[]/parallel[], per-adapter nics[], plus the DB-held
// boot_priority and SSH credentials. raw may be nil (no VM behind the
// machine): only the DB-held keys answer. file carries the .vbox settings
// (nil when unreadable) — it fills the knobs showvminfo never emits; in
// that format absence means DEFAULT, so those fill in as real values.
func KnobCurrent(machine *Machine, raw map[string]string, osTypeID string, file *vbox.MachineSettings) map[string]any {
	current := map[string]any{}

	settings := ParseConfiguration(machine).Section("settings")
	credentials := map[string]any{}
	if user, ok := settings["vagrant_user"].(string); ok && user != "" {
		credentials["vagrant_user"] = user
	}
	if key, ok := settings["vagrant_user_private_key_path"].(string); ok && key != "" {
		credentials["vagrant_user_private_key_path"] = key
	}
	if pass, ok := settings["vagrant_user_pass"].(string); ok && pass != "" {
		credentials["vagrant_user_pass"] = pass
	}
	if len(credentials) > 0 {
		current["credentials"] = credentials
	}
	if spec, err := ParseSpec(machine); err == nil && spec != nil {
		if priority := intOr(spec.Settings["boot_priority"], 0); priority > 0 {
			current["boot_priority"] = priority
		}
	}
	if raw == nil {
		return current
	}

	setInt(current, "ram", raw, "memory")
	setInt(current, "vcpus", raw, "cpus")
	// firmware="BIOS"|"EFI"|"EFI32"|"EFI64"|"EFIDUAL" → PUT's bios|efi.
	if firmware, ok := raw["firmware"]; ok && firmware != "unknown" {
		if strings.Contains(strings.ToLower(firmware), "efi") {
			current["bootrom"] = "efi"
		} else {
			current["bootrom"] = "bios"
		}
	}
	switch raw["chipset"] {
	case "piix3", "ich9", "armv8virtual":
		current["hostbridge"] = raw["chipset"]
	}
	if diskif := reverseControllerType(raw["storagecontrollertype0"]); diskif != "" {
		current["diskif"] = diskif
	}
	if netif := uniformNetif(raw); netif != "" {
		current["netif"] = netif
	}
	// "ostype" is the DESCRIPTION; the ID PUT takes arrives resolved through
	// `list ostypes`. GuestOSType (console-only, additions-reported) is the
	// fallback.
	if osTypeID == "" {
		osTypeID = raw["GuestOSType"]
	}
	if osTypeID != "" {
		current["os_type"] = osTypeID
	}
	setRaw(current, "vnc", raw, "vrde")
	setRaw(current, "acpi", raw, "acpi")
	setRaw(current, "xhci", raw, "xhci")
	// PUT's autoboot is a boolean (the swagger contract), unlike the on|off
	// string knobs.
	if enabled, ok := raw["autostart-enabled"]; ok {
		current["autoboot"] = enabled == "on"
	}
	if order, expressible := bootOrderCurrent(raw); expressible && len(order) > 0 {
		current["boot_order"] = order
	}
	// guest_agent read back from the wire itself: uart2 in server mode onto
	// the machine's QGA pipe/socket — the Proxmox-style checkbox prefill
	// (always reported, so an unwired machine renders unchecked).
	current["guest_agent"] = guestAgentWired(raw)

	cpu := cpuCurrent(raw)
	audio := audioCurrent(raw)
	usb := usbCurrent(raw)
	platform := platformCurrent(raw)
	firmware := firmwareCurrent(raw)
	recording := recordingCurrent(raw)
	vrde := vrdeCurrent(raw)
	nics := nicsCurrent(raw)
	if file != nil {
		applySettingsFile(file, cpu, audio, usb, platform, firmware, recording, vrde, nics)
	}

	hardware := map[string]any{}
	putSection(hardware, "cpu", cpu)
	putSection(hardware, "memory", memoryCurrent(raw))
	putSection(hardware, "graphics", graphicsCurrent(raw))
	putSection(hardware, "audio", audio)
	putSection(hardware, "usb", usb)
	putSection(hardware, "integration", integrationCurrent(raw))
	putSection(hardware, "platform", platform)
	putSection(hardware, "firmware", firmware)
	putSection(hardware, "recording", recording)
	putSection(hardware, "vrde", vrde)
	putSection(hardware, "autostart", autostartCurrent(raw))
	if serial := serialCurrent(raw); len(serial) > 0 {
		hardware["serial"] = serial
	}
	if parallel := parallelCurrent(raw); len(parallel) > 0 {
		hardware["parallel"] = parallel
	}
	if len(hardware) > 0 {
		current["vbox"] = hardware
	}

	if len(nics) > 0 {
		annotateTransportNics(machine, raw, nics)
		current["nics"] = nics
	}
	current["devices"] = devicesCurrent(raw)
	return current
}

// onOffWord renders a settings-file boolean in the on|off knob vocabulary.
func onOffWord(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// setRaw copies an on|off (or verbatim-legal) key when the emitter printed it.
func setRaw(target map[string]any, name string, raw map[string]string, key string) {
	if value, ok := raw[key]; ok && value != "" {
		target[name] = value
	}
}

// setInt copies a numeric key when the emitter printed one.
func setInt(target map[string]any, name string, raw map[string]string, key string) {
	if value, ok := raw[key]; ok {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			target[name] = n
		}
	}
}

// setEnum copies a closed-vocabulary key, dropping the emitter's
// "unknown"/"invalid" fallbacks (never PUT-legal).
func setEnum(target map[string]any, name string, raw map[string]string, key string) {
	switch value := raw[key]; value {
	case "", "unknown", "invalid":
	default:
		target[name] = value
	}
}

func putSection(hardware map[string]any, name string, section map[string]any) {
	if len(section) > 0 {
		hardware[name] = section
	}
}
