package machines

import (
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// modifyAttributeFlags maps the base's attribute vocabulary onto modifyvm
// (ZoneAttributeModifier's attrMap, translated): ram/vcpus/os_type map
// directly; vnc drives VRDE; bootrom drives firmware; hostbridge drives the
// chipset; netif drives every configured adapter's hardware type; diskif has
// no modifyvm analog and is reported, never silently accepted.
func modifyAttributeFlags(metadata map[string]any, info *vbox.Info) (flags, notes []string, err error) {
	if v, ok := metadata["ram"]; ok {
		flags = append(flags, "--memory="+strconv.FormatInt(memoryToMB(v), 10))
	}
	if v, ok := metadata["vcpus"]; ok {
		// VCPUCount, not intOr (converged v2, sync 2026-07-17): a guard-passed
		// float-string like "4.0" must apply as 4, never the default.
		flags = append(flags, "--cpus="+strconv.FormatInt(VCPUCount(v, 2), 10))
	}
	if v, ok := metadata["os_type"]; ok {
		if s := stringOr(v, ""); s != "" {
			flags = append(flags, "--ostype="+s)
		}
	}
	if v, ok := metadata["vnc"]; ok {
		flags = append(flags, "--vrde="+onOff(v))
	}
	if v, ok := metadata["acpi"]; ok {
		flags = append(flags, "--acpi="+onOff(v))
	}
	if v, ok := metadata["xhci"]; ok {
		flags = append(flags, "--usb-xhci="+onOff(v))
	}
	if v, ok := metadata["bootrom"]; ok {
		firmware := "bios"
		if strings.Contains(strings.ToLower(stringOr(v, "")), "efi") {
			firmware = "efi"
		}
		flags = append(flags, "--firmware="+firmware)
	}
	if v, ok := metadata["hostbridge"]; ok {
		chipset := strings.ToLower(stringOr(v, ""))
		if chipset == "i440fx" {
			// bhyve's PIIX-era hostbridge is VirtualBox's PIIX3 chipset.
			chipset = "piix3"
		}
		if chipset != "" {
			flags = append(flags, "--chipset="+chipset)
		}
	}
	if v, ok := metadata["netif"]; ok {
		if nicType := vboxNICType(stringOr(v, "")); nicType == "" {
			notes = append(notes, "netif value "+stringOr(v, "")+" has no VirtualBox adapter type — skipped")
		} else {
			for n := 1; n <= maxNICSlots; n++ {
				if val, present := info.Raw["nic"+strconv.Itoa(n)]; present && val != "none" {
					flags = append(flags, "--nic-type"+strconv.Itoa(n)+"="+nicType)
				}
			}
		}
	}
	if _, ok := metadata["diskif"]; ok {
		notes = append(notes, "diskif selects the default controller's type at CREATE only — VirtualBox fixes a controller's type once media attach; add a NEW controller via add_controllers instead; skipped")
	}
	if v, ok := metadata["boot_order"]; ok {
		if bootFlags := bootOrderFlags(v); len(bootFlags) > 0 {
			flags = append(flags, bootFlags...)
		} else {
			notes = append(notes, "boot_order carries no usable entries (floppy|dvd|disk|net|none) — skipped")
		}
	}
	if vboxSection := mapOr(metadata["vbox"]); len(vboxSection) > 0 {
		hwFlags, herr := hardwareFlags(vboxSection)
		if herr != nil {
			return nil, nil, herr
		}
		flags = append(flags, hwFlags...)
		for _, entry := range listOr(vboxSection["directives"]) {
			directive := mapOr(entry)
			if name := stringOr(directive["directive"], ""); name != "" {
				flags = append(flags, "--"+name+"="+stringOr(directive["value"], ""))
			}
		}
	}
	return flags, notes, nil
}

// vboxNICType maps the document's netif vocabulary onto VirtualBox adapter
// hardware types ("" when there is no analog).
func vboxNICType(netif string) string {
	switch strings.ToLower(netif) {
	case "virtio":
		return "virtio"
	case "e1000":
		return "82540EM"
	}
	return ""
}
