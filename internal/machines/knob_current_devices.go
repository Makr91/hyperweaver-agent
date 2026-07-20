package machines

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// devicesCurrent serves the structured device tree (the UI's ruled shape,
// sync 2026-07-18 — kills its nic/controller/attachment regexes over the
// flat showvminfo map): controllers by index, attachments by the
// "<Controller>-<port>-<device>" keys (kind cdrom = emptydrive or .iso,
// else disk; an empty drive answers path ""), nics per enabled adapter.
func devicesCurrent(raw map[string]string) map[string]any {
	controllers := []any{}
	names := map[string]bool{}
	for n := 0; ; n++ {
		name, ok := raw["storagecontrollername"+strconv.Itoa(n)]
		if !ok {
			break
		}
		emitted := raw["storagecontrollertype"+strconv.Itoa(n)]
		kind := reverseControllerType(emitted)
		if kind == "" {
			kind = emitted
		}
		names[name] = true
		controllers = append(controllers, map[string]any{"name": name, "type": kind})
	}

	type attachment struct {
		controller   string
		port, device int
		path, kind   string
	}
	rows := []attachment{}
	for key, value := range raw {
		if value == "none" || value == "" || strings.Contains(key, "ImageUUID") {
			continue
		}
		match := attachmentPattern.FindStringSubmatch(key)
		if len(match) < 4 || !names[match[1]] {
			continue
		}
		port, perr := strconv.Atoi(match[2])
		device, derr := strconv.Atoi(match[3])
		if perr != nil || derr != nil {
			continue
		}
		row := attachment{controller: match[1], port: port, device: device, path: value, kind: "disk"}
		if value == "emptydrive" {
			row.path, row.kind = "", "cdrom"
		} else if strings.EqualFold(filepath.Ext(value), ".iso") {
			row.kind = "cdrom"
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].controller != rows[j].controller {
			return rows[i].controller < rows[j].controller
		}
		if rows[i].port != rows[j].port {
			return rows[i].port < rows[j].port
		}
		return rows[i].device < rows[j].device
	})
	attachments := make([]any, 0, len(rows))
	for _, row := range rows {
		attachments = append(attachments, map[string]any{
			"controller": row.controller, "port": row.port, "device": row.device,
			"path": row.path, "kind": row.kind,
		})
	}

	deviceNics := []any{}
	for adapter := 1; adapter <= maxNICSlots; adapter++ {
		n := strconv.Itoa(adapter)
		mode, ok := raw["nic"+n]
		if !ok || mode == "none" {
			continue
		}
		entry := map[string]any{"adapter": adapter, "mode": mode}
		if target := nicTargetName(raw, mode, n); target != "" {
			entry["network"] = target
		}
		if mac := raw["macaddress"+n]; mac != "" {
			entry["mac"] = mac
		}
		deviceNics = append(deviceNics, entry)
	}
	return map[string]any{"controllers": controllers, "attachments": attachments, "nics": deviceNics}
}

// nicTargetName resolves an adapter's attachment TARGET from the emitter's
// per-mode key (the UI's adapter → network-space join, sync 2026-07-19 —
// bridge?'s replacement, one field for every mode). The nat-network /
// hostonly-network / generic-driver spellings are emitter-derived but
// unverified against a live machine in those modes (none exists on Mark's
// host); natnetwork additionally tries the older natnet<N> spelling.
func nicTargetName(raw map[string]string, mode, n string) string {
	switch mode {
	case "bridged":
		return raw["bridgeadapter"+n]
	case "hostonly":
		return raw["hostonlyadapter"+n]
	case "intnet":
		return raw["intnet"+n]
	case "natnetwork":
		if name := raw["nat-network"+n]; name != "" {
			return name
		}
		return raw["natnet"+n]
	case "hostonlynetwork":
		return raw["hostonly-network"+n]
	case "generic":
		return raw["generic-driver"+n]
	}
	return ""
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
