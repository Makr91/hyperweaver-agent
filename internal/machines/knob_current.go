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
		current["hardware"] = hardware
	}

	if len(nics) > 0 {
		annotateTransportNics(machine, raw, nics)
		current["nics"] = nics
	}
	return current
}

// annotateTransportNics stamps the transport/provisional markers onto the
// nics[] rows (the converged flip wire, sync 2026-07-18 — UI's badge +
// toggle feed): adapter 1 gets provisional: true + the EFFECTIVE
// remove_on_completion (settings.remove_transport_on_completion, absent =
// this agent's ruled default false) when it IS the provisioning NAT
// transport (attachment nat with the marker MAC — 00FF00FF00FF, Hosts.rb's
// own vagrant-NAT identity); adapters 2+ mirror their document networks[]
// entry's provisional flag and — on provisional or explicitly-flagged
// entries — the effective remove_on_completion. The declared pairing rule:
// nics[] row adapter N ↔ networks[N-2].
func annotateTransportNics(machine *Machine, raw map[string]string, nics []any) {
	config := ParseConfiguration(machine)
	settings := config.Section("settings")
	networks := config.List("networks")
	transportFlag, _ := settings["remove_transport_on_completion"].(bool)
	for _, entry := range nics {
		nic, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		adapter, _ := nic["adapter"].(int)
		if adapter == 1 {
			if raw["nic1"] == "nat" && strings.EqualFold(raw["macaddress1"], "00FF00FF00FF") {
				nic["provisional"] = true
				nic["remove_on_completion"] = transportFlag
			}
			continue
		}
		index := adapter - 2
		if index < 0 || index >= len(networks) {
			continue
		}
		network := mapOr(networks[index])
		provisional, _ := network["provisional"].(bool)
		if provisional {
			nic["provisional"] = true
		}
		if flag, has := network["remove_on_completion"].(bool); has {
			nic["remove_on_completion"] = flag
		} else if provisional {
			// The effective value of an absent flag — this agent's ruled
			// default (false: keep).
			nic["remove_on_completion"] = false
		}
	}
}

// applySettingsFile fills the showvminfo-gap knobs from the .vbox settings,
// translated into modifyvm's words (the XML→flag vocabulary pairs read from
// Settings.cpp and VBoxManageModifyVM.cpp).
func applySettingsFile(ms *vbox.MachineSettings,
	cpu, audio, usb, platform, firmware, recording, vrde map[string]any, nics []any,
) {
	cpu["hotplug"] = onOffWord(ms.CPUHotplug)
	cpu["spec_ctrl"] = onOffWord(ms.SpecCtrl)
	cpu["ibpb_on_vm_exit"] = onOffWord(ms.IBPBOnVMExit)
	cpu["ibpb_on_vm_entry"] = onOffWord(ms.IBPBOnVMEntry)
	cpu["l1d_flush_on_sched"] = onOffWord(ms.L1DFlushOnSched)
	cpu["l1d_flush_on_vm_entry"] = onOffWord(ms.L1DFlushOnVMEntry)
	cpu["mds_clear_on_sched"] = onOffWord(ms.MDSClearOnSched)
	cpu["mds_clear_on_vm_entry"] = onOffWord(ms.MDSClearOnVMEntry)
	if ms.ArmGicIts != nil {
		cpu["arm_gic_its"] = onOffWord(*ms.ArmGicIts)
	}

	// XML words → modifyvm words; Virtio-Sound has no modifyvm word yet and
	// rides lowercased (unknown values stay selectable by contract).
	switch ms.AudioController {
	case "AC97":
		audio["controller"] = "ac97"
	case "SB16":
		audio["controller"] = "sb16"
	case "HDA":
		audio["controller"] = "hda"
	case "Virtio-Sound":
		audio["controller"] = "virtio-sound"
	}
	switch ms.AudioCodec {
	case "STAC9700":
		audio["codec"] = "stac9700"
	case "STAC9221":
		audio["codec"] = "stac9221"
	case "AD1980":
		audio["codec"] = "ad1980"
	case "SB16":
		audio["codec"] = "sb16"
	}

	usb["card_reader"] = onOffWord(ms.CardReader)

	switch ms.TPMType {
	case "None":
		platform["tpm_type"] = "none"
	case "v1_2":
		platform["tpm_type"] = "1.2"
	case "v2_0":
		platform["tpm_type"] = "2.0"
	case "Host":
		platform["tpm_type"] = "host"
	case "Swtpm":
		platform["tpm_type"] = "swtpm"
	}
	if ms.TPMLocation != "" {
		platform["tpm_location"] = ms.TPMLocation
	}
	platform["system_uuid_le"] = onOffWord(ms.SmbiosUUIDLE)
	switch ms.ExecutionEngine {
	case "HwVirt":
		platform["vm_execution_engine"] = "hwvirt"
	case "NativeApi":
		platform["vm_execution_engine"] = "native-api"
	case "Interpreter":
		platform["vm_execution_engine"] = "interpreter"
	case "Recompiler":
		platform["vm_execution_engine"] = "recompiler"
	default:
		platform["vm_execution_engine"] = "default"
	}

	firmware["logo_fade_in"] = onOffWord(ms.LogoFadeIn)
	firmware["logo_fade_out"] = onOffWord(ms.LogoFadeOut)
	firmware["logo_display_time"] = ms.LogoDisplayTime
	if ms.LogoImagePath != "" {
		firmware["logo_image_path"] = ms.LogoImagePath
	}
	firmware["pxe_debug"] = onOffWord(ms.PXEDebug)

	// "" is the unset store value; modifyvm's word for it is "default".
	vrde["auth_library"] = orDefault(ms.VRDEAuthLibrary, "default")
	vrde["extpack"] = orDefault(ms.VRDEExtPack, "default")

	recording["max_time_seconds"] = ms.RecordingMaxTimeS
	recording["max_size_mb"] = ms.RecordingMaxSizeMB

	for _, entry := range nics {
		nic, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		adapter, _ := nic["adapter"].(int)
		settings, known := ms.Adapters[adapter]
		if !known {
			// Absent adapters carry the constructor defaults.
			settings = vbox.AdapterSettings{Promisc: "Deny"}
		}
		switch settings.Promisc {
		case "AllowNetwork":
			nic["promisc"] = "allow-vms"
		case "AllowAll":
			nic["promisc"] = "allow-all"
		default:
			nic["promisc"] = "deny"
		}
		nic["boot_prio"] = settings.BootPriority
		if settings.BandwidthGroup != "" {
			nic["bandwidth_group"] = settings.BandwidthGroup
		}
	}
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

func cpuCurrent(raw map[string]string) map[string]any {
	cpu := map[string]any{}
	setInt(cpu, "execution_cap", raw, "cpuexecutioncap")
	setRaw(cpu, "profile", raw, "cpu-profile")
	setRaw(cpu, "pae", raw, "pae")
	setRaw(cpu, "long_mode", raw, "longmode")
	setRaw(cpu, "hwvirtex", raw, "hwvirtex")
	setRaw(cpu, "nested_paging", raw, "nestedpaging")
	setRaw(cpu, "large_pages", raw, "largepages")
	setRaw(cpu, "nested_hw_virt", raw, "nested-hw-virt")
	setRaw(cpu, "virt_vmsave_vmload", raw, "virtvmsavevmload")
	setRaw(cpu, "vtx_vpid", raw, "vtxvpid")
	setRaw(cpu, "vtx_ux", raw, "vtxux")
	setRaw(cpu, "apic", raw, "apic")
	setRaw(cpu, "x2apic", raw, "x2apic")
	setRaw(cpu, "hpet", raw, "hpet")
	setRaw(cpu, "arm_gic_its", raw, "gic-its")
	setInt(cpu, "cpuid_portability_level", raw, "cpuid-portability-level")
	return cpu
}

func memoryCurrent(raw map[string]string) map[string]any {
	memory := map[string]any{}
	setInt(memory, "vram", raw, "vram")
	setRaw(memory, "page_fusion", raw, "pagefusion")
	setInt(memory, "balloon", raw, "GuestMemoryBalloon")
	return memory
}

func graphicsCurrent(raw map[string]string) map[string]any {
	graphics := map[string]any{}
	// The emitter's GraphicsControllerType_Null is "null"; modifyvm's word
	// for it is "none".
	switch controller := raw["graphicscontroller"]; controller {
	case "", "unknown":
	case "null":
		graphics["controller"] = "none"
	default:
		graphics["controller"] = controller
	}
	setInt(graphics, "monitor_count", raw, "monitorcount")
	setRaw(graphics, "accelerate_3d", raw, "accelerate3d")
	return graphics
}

// audioCurrent: audio="none" MEANS disabled (the emitter substitutes "none"
// for the driver when the adapter is off); any other value is the driver of
// an enabled adapter.
func audioCurrent(raw map[string]string) map[string]any {
	audio := map[string]any{}
	switch driver := raw["audio"]; driver {
	case "":
	case "none":
		audio["enabled"] = "off"
	case "unknown":
		audio["enabled"] = "on"
	default:
		audio["enabled"] = "on"
		audio["driver"] = driver
	}
	setRaw(audio, "in", raw, "audio_in")
	setRaw(audio, "out", raw, "audio_out")
	return audio
}

func usbCurrent(raw map[string]string) map[string]any {
	usb := map[string]any{}
	// The emitter's OHCI key is literally "usb".
	setRaw(usb, "ohci", raw, "usb")
	setRaw(usb, "ehci", raw, "ehci")
	setRaw(usb, "xhci", raw, "xhci")
	return usb
}

// hidpointing/hidkeyboard emit device names; modifyvm --mouse/--keyboard take
// bus words. combomouse/combokbd have no modifyvm word — omitted.
var mouseCurrentByHID = map[string]string{
	"none": "none", "ps2mouse": "ps2", "usbmouse": "usb", "usbtablet": "usbtablet", "usbmultitouch": "usbmultitouch",
}

var keyboardCurrentByHID = map[string]string{
	"none": "none", "ps2kbd": "ps2", "usbkbd": "usb",
}

func integrationCurrent(raw map[string]string) map[string]any {
	integration := map[string]any{}
	setEnum(integration, "clipboard_mode", raw, "clipboard")
	// on|off from the emitter; modifyvm takes enabled|disabled.
	switch raw["clipboard_file_transfers"] {
	case "on":
		integration["clipboard_file_transfers"] = "enabled"
	case "off":
		integration["clipboard_file_transfers"] = "disabled"
	}
	setEnum(integration, "drag_and_drop", raw, "draganddrop")
	if mouse, ok := mouseCurrentByHID[raw["hidpointing"]]; ok {
		integration["mouse"] = mouse
	}
	if keyboard, ok := keyboardCurrentByHID[raw["hidkeyboard"]]; ok {
		integration["keyboard"] = keyboard
	}
	return integration
}

func platformCurrent(raw map[string]string) map[string]any {
	platform := map[string]any{}
	setEnum(platform, "chipset", raw, "chipset")
	setEnum(platform, "iommu", raw, "iommu")
	setRaw(platform, "rtc_use_utc", raw, "rtcuseutc")
	setEnum(platform, "paravirt_provider", raw, "paravirtprovider")
	setRaw(platform, "ioapic", raw, "ioapic")
	setRaw(platform, "triple_fault_reset", raw, "triplefaultreset")
	setRaw(platform, "hardware_uuid", raw, "hardwareuuid")
	setRaw(platform, "snapshot_folder", raw, "SnapFldr")
	setRaw(platform, "description", raw, "description")
	setRaw(platform, "groups", raw, "groups")
	setRaw(platform, "default_frontend", raw, "defaultfrontend")
	setEnum(platform, "vm_process_priority", raw, "vmprocpriority")
	return platform
}

func firmwareCurrent(raw map[string]string) map[string]any {
	firmware := map[string]any{}
	setEnum(firmware, "boot_menu", raw, "bootmenu")
	setEnum(firmware, "apic", raw, "biosapic")
	setInt(firmware, "system_time_offset", raw, "biossystemtimeoffset")
	return firmware
}

// recordingCurrent: the rec_screen_* keys carry no screen index — on
// multi-monitor machines the live view holds the LAST screen's values, which
// is also what the VM-wide modifyvm recording knobs address.
func recordingCurrent(raw map[string]string) map[string]any {
	recording := map[string]any{}
	setRaw(recording, "enabled", raw, "recording_enabled")
	setRaw(recording, "file", raw, "rec_screen_dest_filename")
	setRaw(recording, "opts", raw, "rec_screen_opts")
	setInt(recording, "video_fps", raw, "rec_screen_video_fps")
	setInt(recording, "video_rate", raw, "rec_screen_video_rate_kbps")
	setRaw(recording, "video_res", raw, "rec_screen_video_res_xy")
	return recording
}

// vrdeCurrent: a disabled server emits ONLY vrde="off" — every sub-key is
// unknowable then. vrdeports is the configured knob; vrdeport is the live
// runtime port and deliberately not a knob.
func vrdeCurrent(raw map[string]string) map[string]any {
	vrde := map[string]any{}
	setRaw(vrde, "enabled", raw, "vrde")
	setRaw(vrde, "port", raw, "vrdeports")
	setRaw(vrde, "address", raw, "vrdeaddress")
	setEnum(vrde, "auth_type", raw, "vrdeauthtype")
	setRaw(vrde, "multi_con", raw, "vrdemulticon")
	setRaw(vrde, "reuse_con", raw, "vrdereusecon")
	setRaw(vrde, "video_channel", raw, "vrdevideochannel")
	setInt(vrde, "video_channel_quality", raw, "vrdevideochannelquality")
	return vrde
}

func autostartCurrent(raw map[string]string) map[string]any {
	autostart := map[string]any{}
	setRaw(autostart, "enabled", raw, "autostart-enabled")
	setInt(autostart, "delay", raw, "autostart-delay")
	return autostart
}

// guestAgentWired reports whether uart2 carries the QGA channel: enabled, in
// server mode, onto a hyperweaver-qga pipe (Windows hosts) or qga.sock
// (elsewhere) — PUT's guest_agent toggle read backwards.
func guestAgentWired(raw map[string]string) bool {
	if _, _, ok := splitPortValue(raw["uart2"]); !ok {
		return false
	}
	kind, path, found := strings.Cut(raw["uartmode2"], ",")
	if !found || kind != "server" {
		return false
	}
	return strings.Contains(path, "hyperweaver-qga-") || strings.HasSuffix(path, "qga.sock")
}

// serialCurrent reads uartN="io_base,irq" + uartmodeN + uarttypeN into
// hardware.serial[] entries. Disabled ports (uartN="off") are unset — omitted.
func serialCurrent(raw map[string]string) []any {
	entries := []any{}
	for port := 1; port <= 4; port++ {
		n := strconv.Itoa(port)
		ioBase, irq, ok := splitPortValue(raw["uart"+n])
		if !ok {
			continue
		}
		entry := map[string]any{"port": port, "io_base": ioBase, "irq": irq}
		if mode := serialModeCurrent(raw["uartmode"+n]); mode != "" {
			entry["mode"] = mode
		}
		if uartType := raw["uarttype"+n]; uartType != "" {
			entry["type"] = uartType
		}
		entries = append(entries, entry)
	}
	return entries
}

// serialModeCurrent turns the emitter's "kind,path" forms into PUT's
// space-separated --uart-mode words; disconnected and bare host-device paths
// ride verbatim.
func serialModeCurrent(mode string) string {
	kind, path, found := strings.Cut(mode, ",")
	if !found {
		return mode
	}
	switch kind {
	case "file", "tcpserver", "tcpclient", "server", "client":
		return kind + " " + path
	}
	return mode
}

// parallelCurrent reads lptN="io_base,irq" + lptmodeN into
// hardware.parallel[] entries.
func parallelCurrent(raw map[string]string) []any {
	entries := []any{}
	for port := 1; port <= 2; port++ {
		n := strconv.Itoa(port)
		ioBase, irq, ok := splitPortValue(raw["lpt"+n])
		if !ok {
			continue
		}
		entry := map[string]any{"port": port, "io_base": ioBase, "irq": irq}
		if device := raw["lptmode"+n]; device != "" {
			entry["device"] = device
		}
		entries = append(entries, entry)
	}
	return entries
}

// splitPortValue parses the emitter's enabled-port "0x03f8,4" form; "off",
// absence, and malformed values answer !ok.
func splitPortValue(value string) (ioBase string, irq int64, ok bool) {
	if value == "" || value == "off" {
		return "", 0, false
	}
	ioBase, irqText, found := strings.Cut(value, ",")
	if !found {
		return "", 0, false
	}
	irq, err := strconv.ParseInt(irqText, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return ioBase, irq, true
}

// nicsCurrent builds the per-adapter tuning list (PUT's nics[] vocabulary)
// for every enabled adapter. promisc/boot_prio/bandwidth_group never emit
// machinereadable — unknowable, omitted.
func nicsCurrent(raw map[string]string) []any {
	nics := []any{}
	for adapter := 1; adapter <= maxNICSlots; adapter++ {
		n := strconv.Itoa(adapter)
		if attachment, ok := raw["nic"+n]; !ok || attachment == "none" {
			continue
		}
		entry := map[string]any{"adapter": adapter}
		if cable, ok := raw["cableconnected"+n]; ok {
			entry["cable_connected"] = cable
		}
		if nicType := raw["nictype"+n]; nicType != "" && nicType != "unknown" {
			entry["nic_type"] = nicType
		}
		if mac := raw["macaddress"+n]; mac != "" {
			entry["mac"] = mac
		}
		if speed, err := strconv.ParseInt(raw["nicspeed"+n], 10, 64); err == nil {
			entry["speed"] = speed
		}
		nics = append(nics, entry)
	}
	return nics
}

// reverseControllerType maps the emitter's controller-type names onto the
// document's diskif/controller_type words (storageControllerKind backwards).
func reverseControllerType(emitted string) string {
	switch emitted {
	case "IntelAhci":
		return "sata"
	case "PIIX3", "PIIX4", "ICH6":
		return "ide"
	case "LsiLogic", "BusLogic":
		return "scsi"
	case "LsiLogicSas":
		return "sas"
	case "NVMe":
		return "nvme"
	case "VirtioSCSI":
		return "virtio"
	case "USB":
		return "usb"
	case "I82078":
		return "floppy"
	}
	return ""
}

// uniformNetif answers PUT's coarse netif ONLY when every enabled adapter
// carries the type netif would set (vboxNICType backwards); mixed or other
// hardware stays per-adapter in nics[].
func uniformNetif(raw map[string]string) string {
	netif := ""
	for adapter := 1; adapter <= maxNICSlots; adapter++ {
		n := strconv.Itoa(adapter)
		if attachment, ok := raw["nic"+n]; !ok || attachment == "none" {
			continue
		}
		var candidate string
		switch raw["nictype"+n] {
		case "82540EM":
			candidate = "e1000"
		case "virtio":
			candidate = "virtio"
		default:
			return ""
		}
		if netif == "" {
			netif = candidate
		} else if netif != candidate {
			return ""
		}
	}
	return netif
}

// bootOrderCurrent reads boot1..bootN into PUT's boot_order list. Slots
// carrying devices PUT cannot express (usb/sharedfolder) make the whole key
// inexpressible — omitted rather than silently reordered.
func bootOrderCurrent(raw map[string]string) (order []string, expressible bool) {
	order = []string{}
	for slot := 1; ; slot++ {
		value, ok := raw["boot"+strconv.Itoa(slot)]
		if !ok {
			return order, true
		}
		switch value {
		case "floppy", "dvd", "disk", "net":
			order = append(order, value)
		case "none":
		default:
			return nil, false
		}
	}
}
