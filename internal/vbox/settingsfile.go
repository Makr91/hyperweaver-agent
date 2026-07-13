package vbox

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
)

// The .vbox machine-settings reader — the knobs showvminfo never emits, read
// from VirtualBox's own persisted XML (grounded in Settings.cpp, 7.2.8
// source: element/attribute names from the writer, defaults from the
// constructors). The format's rule is ABSENCE = DEFAULT (the writer omits
// constructor defaults), so unlike the machinereadable view every field here
// is knowable. Both on-disk layout versions VirtualBox reads are handled:
// settings <1.20 keep the x86/firmware bits under Hardware (CPU/BIOS),
// >=1.20 moved them to Platform/x86 and Firmware.

// MachineSettings is the showvminfo-gap knob set with Settings.cpp's
// defaults applied. String values carry the XML words (AC97, v1_2, HwVirt,
// Deny...) — callers translate to their own vocabularies.
type MachineSettings struct {
	CPUHotplug         bool
	SpecCtrl           bool
	IBPBOnVMExit       bool
	IBPBOnVMEntry      bool
	L1DFlushOnSched    bool // defaults TRUE
	L1DFlushOnVMEntry  bool
	MDSClearOnSched    bool // defaults TRUE
	MDSClearOnVMEntry  bool
	ArmGicIts          *bool // nil on x86 machines
	AudioController    string
	AudioCodec         string
	CardReader         bool
	TPMType            string
	TPMLocation        string
	VRDEAuthLibrary    string // "" = default
	VRDEExtPack        string // "" = default
	LogoFadeIn         bool   // defaults TRUE
	LogoFadeOut        bool   // defaults TRUE
	LogoDisplayTime    int64
	LogoImagePath      string
	PXEDebug           bool
	SmbiosUUIDLE       bool
	ExecutionEngine    string // "" = Default
	RecordingMaxTimeS  int64
	RecordingMaxSizeMB int64
	// Adapters carries per-adapter values keyed by the 1-BASED adapter
	// number (the XML slot attribute is 0-based).
	Adapters map[int]AdapterSettings
}

// AdapterSettings is one adapter's showvminfo-gap values.
type AdapterSettings struct {
	Promisc        string // Deny | AllowNetwork | AllowAll
	BootPriority   int64
	BandwidthGroup string
}

type settingsEnabledXML struct {
	Enabled bool `xml:"enabled,attr"`
}

type settingsSchedXML struct {
	// scheduling is only written when false (default true) — pointer keeps
	// element-present-attribute-absent honest.
	Scheduling *bool `xml:"scheduling,attr"`
	VMEntry    bool  `xml:"vmentry,attr"`
}

type settingsCPUXML struct {
	Hotplug  bool                `xml:"hotplug,attr"`
	SpecCtrl *settingsEnabledXML `xml:"SpecCtrl"`
	IBPBOn   *struct {
		VMExit  bool `xml:"vmexit,attr"`
		VMEntry bool `xml:"vmentry,attr"`
	} `xml:"IBPBOn"`
	L1DFlushOn *settingsSchedXML `xml:"L1DFlushOn"`
	MDSClearOn *settingsSchedXML `xml:"MDSClearOn"`
}

type settingsFirmwareBitsXML struct {
	Logo *struct {
		FadeIn      *bool  `xml:"fadeIn,attr"`
		FadeOut     *bool  `xml:"fadeOut,attr"`
		DisplayTime int64  `xml:"displayTime,attr"`
		ImagePath   string `xml:"imagePath,attr"`
	} `xml:"Logo"`
	PXEDebug     *settingsEnabledXML `xml:"PXEDebug"`
	SmbiosUUIDLE *settingsEnabledXML `xml:"SmbiosUuidLittleEndian"`
}

type settingsXML struct {
	Machine struct {
		UUID            string `xml:"uuid,attr"`
		ExecutionEngine string `xml:"executionEngine,attr"`
		Platform        *struct {
			X86 *struct {
				CPU *settingsCPUXML `xml:"CPU"`
			} `xml:"x86"`
			ARM *struct {
				CPU *struct {
					GicIts *settingsEnabledXML `xml:"GicIts"`
				} `xml:"CPU"`
			} `xml:"arm"`
			CPU *settingsCPUXML `xml:"CPU"` // hotplug lives on the generic CPU node
		} `xml:"Platform"`
		Hardware struct {
			CPU           *settingsCPUXML          `xml:"CPU"`  // settings <1.20
			BIOS          *settingsFirmwareBitsXML `xml:"BIOS"` // settings <1.20
			Firmware      *settingsFirmwareBitsXML `xml:"Firmware"`
			RemoteDisplay *struct {
				AuthLibrary string `xml:"authLibrary,attr"`
				ExtPack     string `xml:"VRDEExtPack,attr"`
			} `xml:"RemoteDisplay"`
			AudioAdapter *struct {
				Controller string `xml:"controller,attr"`
				Codec      string `xml:"codec,attr"`
			} `xml:"AudioAdapter"`
			Network struct {
				Adapters []struct {
					Slot           int    `xml:"slot,attr"`
					Promisc        string `xml:"promiscuousModePolicy,attr"`
					BootPriority   int64  `xml:"bootPriority,attr"`
					BandwidthGroup string `xml:"bandwidthGroup,attr"`
				} `xml:"Adapter"`
			} `xml:"Network"`
			EmulatedUSB *struct {
				CardReader *settingsEnabledXML `xml:"CardReader"`
			} `xml:"EmulatedUSB"`
			TPM *struct {
				Type     string `xml:"type,attr"`
				Location string `xml:"location,attr"`
			} `xml:"TrustedPlatformModule"`
		} `xml:"Hardware"`
		Recording *struct {
			Screens []struct {
				ID        int   `xml:"id,attr"`
				MaxTimeS  int64 `xml:"maxTimeS,attr"`
				MaxSizeMB int64 `xml:"maxSizeMB,attr"`
			} `xml:"Screen"`
		} `xml:"Recording"`
	} `xml:"Machine"`
}

// audioCodecDefault is the per-controller codec Settings.cpp assigns when the
// codec attribute is absent.
func audioCodecDefault(controller string) string {
	switch controller {
	case "SB16":
		return "SB16"
	case "HDA":
		return "STAC9221"
	case "Virtio-Sound":
		return ""
	}
	return "STAC9700" // AC97, the controller default
}

// ReadMachineSettings parses a machine's .vbox file into the gap knob set.
// Encrypted machines (MachineEncrypted root child) and parse failures answer
// an error — callers omit the gap knobs then, staying honest.
func ReadMachineSettings(path string) (*MachineSettings, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	parsed := settingsXML{}
	if uerr := xml.Unmarshal(raw, &parsed); uerr != nil {
		return nil, uerr
	}
	machine := &parsed.Machine
	if machine.UUID == "" {
		return nil, errors.New("no plain Machine element (encrypted settings?)")
	}

	// Settings.cpp constructor defaults.
	ms := &MachineSettings{
		L1DFlushOnSched: true,
		MDSClearOnSched: true,
		LogoFadeIn:      true,
		LogoFadeOut:     true,
		AudioController: "AC97",
		TPMType:         "None",
		ExecutionEngine: machine.ExecutionEngine,
		Adapters:        map[int]AdapterSettings{},
	}

	// The x86 CPU bits: Platform/x86/CPU (>=1.20) or Hardware/CPU (<1.20);
	// hotplug rides the generic CPU node in both layouts.
	cpu := machine.Hardware.CPU
	if machine.Platform != nil {
		if machine.Platform.CPU != nil {
			ms.CPUHotplug = machine.Platform.CPU.Hotplug
		}
		if machine.Platform.X86 != nil && machine.Platform.X86.CPU != nil {
			cpu = machine.Platform.X86.CPU
		}
		if machine.Platform.ARM != nil && machine.Platform.ARM.CPU != nil {
			enabled := machine.Platform.ARM.CPU.GicIts != nil && machine.Platform.ARM.CPU.GicIts.Enabled
			ms.ArmGicIts = &enabled
		}
	}
	if cpu != nil {
		if machine.Platform == nil {
			ms.CPUHotplug = cpu.Hotplug
		}
		if cpu.SpecCtrl != nil {
			ms.SpecCtrl = cpu.SpecCtrl.Enabled
		}
		if cpu.IBPBOn != nil {
			ms.IBPBOnVMExit = cpu.IBPBOn.VMExit
			ms.IBPBOnVMEntry = cpu.IBPBOn.VMEntry
		}
		if cpu.L1DFlushOn != nil {
			if cpu.L1DFlushOn.Scheduling != nil {
				ms.L1DFlushOnSched = *cpu.L1DFlushOn.Scheduling
			}
			ms.L1DFlushOnVMEntry = cpu.L1DFlushOn.VMEntry
		}
		if cpu.MDSClearOn != nil {
			if cpu.MDSClearOn.Scheduling != nil {
				ms.MDSClearOnSched = *cpu.MDSClearOn.Scheduling
			}
			ms.MDSClearOnVMEntry = cpu.MDSClearOn.VMEntry
		}
	}

	if audio := machine.Hardware.AudioAdapter; audio != nil && audio.Controller != "" {
		ms.AudioController = audio.Controller
	}
	ms.AudioCodec = audioCodecDefault(ms.AudioController)
	if audio := machine.Hardware.AudioAdapter; audio != nil && audio.Codec != "" {
		ms.AudioCodec = audio.Codec
	}

	if usb := machine.Hardware.EmulatedUSB; usb != nil && usb.CardReader != nil {
		ms.CardReader = usb.CardReader.Enabled
	}
	if tpm := machine.Hardware.TPM; tpm != nil {
		if tpm.Type != "" {
			ms.TPMType = tpm.Type
		}
		ms.TPMLocation = tpm.Location
	}
	if vrde := machine.Hardware.RemoteDisplay; vrde != nil {
		ms.VRDEAuthLibrary = vrde.AuthLibrary
		ms.VRDEExtPack = vrde.ExtPack
	}

	// The firmware extras: Firmware (>=1.20) or BIOS (<1.20) — <1.20 also
	// writes a Firmware element but it carries only the type.
	bits := machine.Hardware.BIOS
	if bits == nil {
		bits = machine.Hardware.Firmware
	}
	if bits != nil {
		if bits.Logo != nil {
			if bits.Logo.FadeIn != nil {
				ms.LogoFadeIn = *bits.Logo.FadeIn
			}
			if bits.Logo.FadeOut != nil {
				ms.LogoFadeOut = *bits.Logo.FadeOut
			}
			ms.LogoDisplayTime = bits.Logo.DisplayTime
			ms.LogoImagePath = bits.Logo.ImagePath
		}
		if bits.PXEDebug != nil {
			ms.PXEDebug = bits.PXEDebug.Enabled
		}
		if bits.SmbiosUUIDLE != nil {
			ms.SmbiosUUIDLE = bits.SmbiosUUIDLE.Enabled
		}
	}

	// The VM-wide recording knobs live per screen — screen 0 speaks for the
	// machine (only non-default screens are serialized; absence = defaults).
	if machine.Recording != nil {
		for _, screen := range machine.Recording.Screens {
			if screen.ID == 0 {
				ms.RecordingMaxTimeS = screen.MaxTimeS
				ms.RecordingMaxSizeMB = screen.MaxSizeMB
			}
		}
	}

	for _, adapter := range machine.Hardware.Network.Adapters {
		promisc := adapter.Promisc
		if promisc == "" {
			promisc = "Deny"
		}
		ms.Adapters[adapter.Slot+1] = AdapterSettings{
			Promisc:        promisc,
			BootPriority:   adapter.BootPriority,
			BandwidthGroup: adapter.BandwidthGroup,
		}
	}
	return ms, nil
}
