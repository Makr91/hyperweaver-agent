package machines

import "github.com/Makr91/hyperweaver-agent/internal/vbox"

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
