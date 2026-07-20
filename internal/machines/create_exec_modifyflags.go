package machines

import (
	"fmt"
	"strconv"
	"strings"
)

// modifyFlags assembles the modifyvm set FROM THE DOCUMENT — zoneweaver's
// model: core config + the document-driven attribute map, nothing hardcoded.
// settings drive resources/console/firmware, networks[] drive the adapters,
// and vbox.directives is the generic passthrough (the zonecfg attr-map
// analog). Adapter 1 is vagrant's reserved NAT (Mark's ruling 2026-07-07):
// guest internet egress AND the layout every provisioner assumes — the role
// stacks were built for vagrant's NAT-first guests on BOTH hypervisors
// (vagrant-zones emulated it on bhyve; runtime-proven: the networking role
// refuses guests with fewer than two interfaces). Document networks occupy
// adapters 2+ (host-type entries ride hostOnlyAdapter — the provisioning
// network's interface, or its hostonlynet NAME on macOS, Oracle's split).
func modifyFlags(document MachineConfig, hostOnlyAdapter string, sshForwardPort, winrmForwardPort int) ([]string, error) {
	settings := document.Section("settings")
	flags := []string{
		// Browser-RDP-era defaults (Mark's directive 2026-07-10, after live
		// multi-connection testing): absolute pointer + USB keyboard + xHCI
		// for usable consoles, bidirectional clipboard, and a VRDE server
		// that takes parallel clients and keeps the guest session across
		// reconnects. Emitted FIRST — any document knob later in the flag
		// list overrides (modifyvm's last occurrence wins).
		"--mouse=usbtablet",
		"--keyboard=usb",
		"--usb-xhci=on",
		"--clipboard-mode=bidirectional",
		"--clipboard-file-transfers=enabled",
		"--vrde-multi-con=on",
		"--vrde-reuse-con=on",
		// VCPUCount, not intOr (converged v2, sync 2026-07-17): a guard-passed
		// float-string like "4.0" must apply as 4, never the default.
		"--cpus=" + strconv.FormatInt(VCPUCount(settings["vcpus"], 2), 10),
		"--memory=" + strconv.FormatInt(memoryToMB(settings["memory"]), 10),
		"--nic1=nat",
		// The NAT adapter's fixed marker MAC — Hosts.rb:310 verbatim
		// (vb.customize --macaddress1 00FF00FF00FF): the role stacks know
		// vagrant's NAT adapter by it.
		"--mac-address1=00FF00FF00FF",
	}
	if sshForwardPort > 0 {
		flags = append(flags,
			fmt.Sprintf("--natpf1=ssh,tcp,127.0.0.1,%d,,22", sshForwardPort))
	}
	if winrmForwardPort > 0 {
		// The winrm communicator's transport forward (W-Q1..W-Q5): the guest
		// port is the RULED winrm_port — re-read here so the rule and its
		// allocation (createConfig) can never disagree on the document.
		winrm, _ := ExtractWinRM(settings)
		flags = append(flags,
			fmt.Sprintf("--natpf1=winrm,tcp,127.0.0.1,%d,,%d", winrmForwardPort, winrm.Port))
	}
	// roles[].port_forwards → --natpf1 rules on the reserved NAT adapter
	// (core/Hosts.rb:312-320's forwarded_port entries {guest, host, ip};
	// implemented per the 2026-07-16 parity ruling, superseding the earlier
	// TODO-only one). Rule names carry the ports, so two roles forwarding the
	// same pair collide loudly in VirtualBox instead of silently doubling.
	portForwards, pfErr := rolePortForwardFlags(document.List("roles"))
	if pfErr != nil {
		return nil, pfErr
	}
	flags = append(flags, portForwards...)
	if port := intOr(settings["consoleport"], 0); port > 0 {
		flags = append(flags, "--vrde=on",
			"--vrde-port="+strconv.FormatInt(port, 10))
		if host := stringOr(settings["consolehost"], ""); host != "" {
			flags = append(flags, "--vrde-address="+host)
		}
	}
	if strings.EqualFold(stringOr(settings["firmware_type"], ""), "UEFI") {
		flags = append(flags, "--firmware=efi")
	}
	// Boot order (--boot1..4): settings.boot_order is an ordered list of
	// floppy|dvd|disk|net|none — the ISO-first install story (attach the ISO,
	// boot dvd before disk). Unset slots after the list are cleared to none so
	// the order is exactly what the document says.
	flags = append(flags, bootOrderFlags(settings["boot_order"])...)

	// Document networks from adapter 2 — adapter 1 is the reserved NAT.
	for i, entry := range document.List("networks") {
		network := mapOr(entry)
		n := strconv.Itoa(i + 2)
		switch stringOr(network["type"], "external") {
		case "host":
			if UseHostOnlyNets() {
				flags = append(flags, "--nic"+n+"=hostonlynet")
				if hostOnlyAdapter != "" {
					flags = append(flags, "--host-only-net"+n+"="+hostOnlyAdapter)
				}
			} else {
				flags = append(flags, "--nic"+n+"=hostonly")
				if hostOnlyAdapter != "" {
					flags = append(flags, "--host-only-adapter"+n+"="+hostOnlyAdapter)
				}
			}
		default:
			flags = append(flags, "--nic"+n+"=bridged")
			if bridge := stringOr(network["bridge"], ""); bridge != "" {
				flags = append(flags, "--bridge-adapter"+n+"="+bridge)
			}
		}
		if mac := stringOr(network["mac"], ""); mac != "" && !strings.EqualFold(mac, "auto") {
			flags = append(flags, "--mac-address"+n+"="+strings.ReplaceAll(mac, ":", ""))
		}
		flags = append(flags, nicExtraFlags(network, n)...)
	}

	if vboxSection := document.Section("vbox"); len(vboxSection) > 0 {
		hwFlags, herr := hardwareFlags(vboxSection)
		if herr != nil {
			return nil, herr
		}
		flags = append(flags, hwFlags...)
	}

	// The vbox.directives passthrough: the document's own modifyvm attributes
	// — the user's final word, after everything.
	for _, entry := range listOr(document.Section("vbox")["directives"]) {
		directive := mapOr(entry)
		if name := stringOr(directive["directive"], ""); name != "" {
			flags = append(flags, "--"+name+"="+stringOr(directive["value"], ""))
		}
	}
	return flags, nil
}

// rolePortForwardFlags reads the document's roles[].port_forwards[] entries
// ({guest, host, ip?} — Hosts.rb:312-320's vocabulary) into --natpf1 rules.
// Malformed ports are a hard error: a forward the author asked for must
// never silently vanish.
func rolePortForwardFlags(roles []any) ([]string, error) {
	flags := []string{}
	for _, entry := range roles {
		role := mapOr(entry)
		roleName := stringOr(role["name"], "role")
		for _, raw := range listOr(role["port_forwards"]) {
			forward := mapOr(raw)
			if len(forward) == 0 {
				continue
			}
			guest := intOr(forward["guest"], 0)
			host := intOr(forward["host"], 0)
			if guest < 1 || guest > 65535 || host < 1 || host > 65535 {
				return nil, fmt.Errorf("role %s port_forwards entries need guest and host ports 1-65535 (got guest=%v host=%v)",
					roleName, forward["guest"], forward["host"])
			}
			hostIP := stringOr(forward["ip"], "")
			flags = append(flags, fmt.Sprintf("--natpf1=pf-%d-%d,tcp,%s,%d,,%d",
				host, guest, hostIP, host, guest))
		}
	}
	return flags, nil
}

// bootOrderFlags maps a boot_order list onto --boot1..4 (VirtualBox's four
// boot slots; values floppy|dvd|disk|net|none). Slots past the list clear to
// none; unknown values are dropped (the flags would 400 the whole modifyvm).
func bootOrderFlags(value any) []string {
	entries := listOr(value)
	if len(entries) == 0 {
		return nil
	}
	flags := []string{}
	slot := 1
	for _, entry := range entries {
		if slot > 4 {
			break
		}
		device := strings.ToLower(stringOr(entry, ""))
		switch device {
		case "floppy", "dvd", "disk", "net", "none":
			flags = append(flags, fmt.Sprintf("--boot%d=%s", slot, device))
			slot++
		}
	}
	if len(flags) == 0 {
		return nil
	}
	for ; slot <= 4; slot++ {
		flags = append(flags, fmt.Sprintf("--boot%d=none", slot))
	}
	return flags
}
