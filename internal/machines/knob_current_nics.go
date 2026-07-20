package machines

import "strconv"

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
