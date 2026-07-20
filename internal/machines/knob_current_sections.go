package machines

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
