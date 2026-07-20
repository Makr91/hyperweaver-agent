package vbox

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Network-space enumeration + NAT-network management beyond the provisioning
// host-only machinery (hostonly.go): `list intnets`, `list natnetworks`, and
// the `natnetwork add|modify|remove|start|stop` family — the /network/spaces
// surface's hypervisor layer. Internal networks are IMPLICIT: they exist
// while a VM references them, carry no attributes, and have no verbs.

// ListIntNets returns the internal network names (`VBoxManage list intnets`
// — bare Name: lines; runtime-proven on Mark's host 2026-07-19).
func ListIntNets(ctx context.Context, vboxManage string) ([]string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "intnets")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list intnets: %w", err)
	}
	names := []string{}
	for _, line := range strings.Split(string(out), "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "Name:"); found {
			if name := strings.TrimSpace(value); name != "" {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// NATNetworkForward is one NAT-network port-forward rule
// (name:proto:[hostip]:hostport:[guestip]:guestport).
type NATNetworkForward struct {
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	HostIP    string `json:"host_ip"`
	HostPort  int    `json:"host_port"`
	GuestIP   string `json:"guest_ip"`
	GuestPort int    `json:"guest_port"`
}

// NATNetworkLoopback is one parsed loopback mapping (the listing's verbatim
// "address=offset" rule line, structured — the cross-agent structured-JSON
// convergence): the host loopback address and its offset into the NAT
// network's range.
type NATNetworkLoopback struct {
	Address string `json:"address"`
	Offset  int    `json:"offset"`
	IPv6    bool   `json:"ipv6"`
}

// NATNetwork is one `list natnetworks` entry.
type NATNetwork struct {
	Name             string
	CIDR             string
	Gateway          string
	Enabled          bool
	DHCPEnabled      bool
	IPv6             bool
	IPv6Prefix       string
	PortForwards4    []NATNetworkForward
	PortForwards6    []NATNetworkForward
	LoopbackMappings []NATNetworkLoopback
}

// ListNATNetworks parses `VBoxManage list natnetworks` — Key: value blocks
// per network, with indented rule lines under the Port-forwarding/loopback
// section headers. Both the "DHCP Server" spelling and the "DHCP Sever" typo
// older VBoxManage builds shipped are accepted (unverifiable on Mark's host
// 2026-07-19 — it carries no NAT networks; the parse is tolerant).
func ListNATNetworks(ctx context.Context, vboxManage string) ([]NATNetwork, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "natnetworks")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list natnetworks: %w", err)
	}

	networks := []NATNetwork{}
	var current *NATNetwork
	section := ""
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			section = ""
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "port-forwarding (ipv4"):
			section = "pf4"
			continue
		case strings.HasPrefix(lower, "port-forwarding (ipv6"):
			section = "pf6"
			continue
		case strings.HasPrefix(lower, "loopback mappings"):
			section = "loopback4"
			if strings.Contains(lower, "ipv6") {
				section = "loopback6"
			}
			continue
		}
		if section != "" && current != nil {
			switch section {
			case "pf4":
				if fw, ok := parseNATForward(trimmed); ok {
					current.PortForwards4 = append(current.PortForwards4, fw)
				}
			case "pf6":
				if fw, ok := parseNATForward(trimmed); ok {
					current.PortForwards6 = append(current.PortForwards6, fw)
				}
			case "loopback4", "loopback6":
				if lb, ok := parseNATLoopback(trimmed, section == "loopback6"); ok {
					current.LoopbackMappings = append(current.LoopbackMappings, lb)
				}
			}
			continue
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Name", "NetworkName":
			networks = append(networks, NATNetwork{Name: value})
			current = &networks[len(networks)-1]
		case "Network":
			if current != nil {
				current.CIDR = value
			}
		case "Gateway":
			if current != nil {
				current.Gateway = value
			}
		case "DHCP Server", "DHCP Sever":
			if current != nil {
				current.DHCPEnabled = strings.EqualFold(value, "Yes")
			}
		case "IPv6", "IPv6 enabled":
			if current != nil {
				current.IPv6 = strings.EqualFold(value, "Yes")
			}
		case "IPv6 Prefix":
			if current != nil {
				current.IPv6Prefix = value
			}
		case "Enabled":
			if current != nil {
				current.Enabled = strings.EqualFold(value, "Yes")
			}
		}
	}
	return networks, nil
}

// parseNATForward reads one listed rule line — bracket-aware so IPv6
// addresses' own colons survive.
func parseNATForward(rule string) (NATNetworkForward, bool) {
	name, rest, ok := strings.Cut(rule, ":")
	if !ok {
		return NATNetworkForward{}, false
	}
	protocol, rest, ok := strings.Cut(rest, ":")
	if !ok {
		return NATNetworkForward{}, false
	}
	hostIP, rest, ok := natRuleBracket(rest)
	if !ok {
		return NATNetworkForward{}, false
	}
	hostPortText, rest, ok := strings.Cut(rest, ":")
	if !ok {
		return NATNetworkForward{}, false
	}
	guestIP, rest, ok := natRuleBracket(rest)
	if !ok {
		return NATNetworkForward{}, false
	}
	hostPort, herr := strconv.Atoi(strings.TrimSpace(hostPortText))
	guestPort, gerr := strconv.Atoi(strings.TrimSpace(rest))
	if herr != nil || gerr != nil {
		return NATNetworkForward{}, false
	}
	return NATNetworkForward{
		Name:      strings.TrimSpace(name),
		Protocol:  strings.ToLower(strings.TrimSpace(protocol)),
		HostIP:    hostIP,
		HostPort:  hostPort,
		GuestIP:   guestIP,
		GuestPort: guestPort,
	}, true
}

// parseNATLoopback reads one listed loopback line ("address=offset").
func parseNATLoopback(rule string, ipv6 bool) (NATNetworkLoopback, bool) {
	address, offsetText, ok := strings.Cut(rule, "=")
	if !ok {
		return NATNetworkLoopback{}, false
	}
	offset, err := strconv.Atoi(strings.TrimSpace(offsetText))
	if err != nil {
		return NATNetworkLoopback{}, false
	}
	return NATNetworkLoopback{
		Address: strings.TrimSpace(address),
		Offset:  offset,
		IPv6:    ipv6,
	}, true
}

// natRuleBracket consumes a leading "[...]" segment (plus its trailing
// colon) and returns the bracket's contents and the remainder.
func natRuleBracket(s string) (inner, rest string, ok bool) {
	if !strings.HasPrefix(s, "[") {
		return "", "", false
	}
	end := strings.Index(s, "]")
	if end < 0 {
		return "", "", false
	}
	return s[1:end], strings.TrimPrefix(s[end+1:], ":"), true
}

// NATForwardRule renders a rule in the natnetwork flag vocabulary.
func NATForwardRule(fw *NATNetworkForward) string {
	return fmt.Sprintf("%s:%s:[%s]:%d:[%s]:%d",
		fw.Name, fw.Protocol, fw.HostIP, fw.HostPort, fw.GuestIP, fw.GuestPort)
}

// NATNetworkOptions carries add/modify's optional knobs — nil/zero values
// skip the flag, so one call sets any subset.
type NATNetworkOptions struct {
	CIDR    string
	Enabled *bool
	DHCP    *bool
	IPv6    *bool
}

func natNetworkFlags(opts NATNetworkOptions) []string {
	flags := []string{}
	if opts.CIDR != "" {
		flags = append(flags, "--network", opts.CIDR)
	}
	if opts.Enabled != nil {
		if *opts.Enabled {
			flags = append(flags, "--enable")
		} else {
			flags = append(flags, "--disable")
		}
	}
	if opts.DHCP != nil {
		flags = append(flags, "--dhcp", natOnOff(*opts.DHCP))
	}
	if opts.IPv6 != nil {
		flags = append(flags, "--ipv6", natOnOff(*opts.IPv6))
	}
	return flags
}

func natOnOff(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

// AddNATNetwork creates a NAT network (`natnetwork add`).
func AddNATNetwork(ctx context.Context, vboxManage, name string, opts NATNetworkOptions) error {
	args := append([]string{"natnetwork", "add", "--netname", name}, natNetworkFlags(opts)...)
	return runSimple(ctx, vboxManage, args...)
}

// ModifyNATNetwork converges an existing NAT network onto the set options.
func ModifyNATNetwork(ctx context.Context, vboxManage, name string, opts NATNetworkOptions) error {
	args := append([]string{"natnetwork", "modify", "--netname", name}, natNetworkFlags(opts)...)
	return runSimple(ctx, vboxManage, args...)
}

// RemoveNATNetwork deletes a NAT network.
func RemoveNATNetwork(ctx context.Context, vboxManage, name string) error {
	return runSimple(ctx, vboxManage, "natnetwork", "remove", "--netname", name)
}

// StartNATNetwork starts a NAT network's service process.
func StartNATNetwork(ctx context.Context, vboxManage, name string) error {
	return runSimple(ctx, vboxManage, "natnetwork", "start", "--netname", name)
}

// StopNATNetwork stops a NAT network's service process.
func StopNATNetwork(ctx context.Context, vboxManage, name string) error {
	return runSimple(ctx, vboxManage, "natnetwork", "stop", "--netname", name)
}

// AddNATNetworkForward appends one port-forward rule.
func AddNATNetworkForward(ctx context.Context, vboxManage, name string, ipv6 bool, fw *NATNetworkForward) error {
	flag := "--port-forward-4"
	if ipv6 {
		flag = "--port-forward-6"
	}
	return runSimple(ctx, vboxManage, "natnetwork", "modify", "--netname", name,
		flag, NATForwardRule(fw))
}

// RemoveNATNetworkForward deletes one port-forward rule by name (the
// documented `--port-forward-4 delete <rulename>` form — unverified live on
// this codebase's own host, no NAT networks exist there yet).
func RemoveNATNetworkForward(ctx context.Context, vboxManage, name, ruleName string, ipv6 bool) error {
	flag := "--port-forward-4"
	if ipv6 {
		flag = "--port-forward-6"
	}
	return runSimple(ctx, vboxManage, "natnetwork", "modify", "--netname", name,
		flag, "delete", ruleName)
}

// AddNATNetworkLoopback appends one loopback mapping (the rule string rides
// verbatim — the listing shows the same form back).
func AddNATNetworkLoopback(ctx context.Context, vboxManage, name string, ipv6 bool, rule string) error {
	flag := "--loopback-4"
	if ipv6 {
		flag = "--loopback-6"
	}
	return runSimple(ctx, vboxManage, "natnetwork", "modify", "--netname", name, flag, rule)
}

// RemoveNATNetworkLoopback deletes one loopback mapping (the port-forward
// family's delete-keyword form — unverified live, same caveat).
func RemoveNATNetworkLoopback(ctx context.Context, vboxManage, name string, ipv6 bool, rule string) error {
	flag := "--loopback-4"
	if ipv6 {
		flag = "--loopback-6"
	}
	return runSimple(ctx, vboxManage, "natnetwork", "modify", "--netname", name, flag, "delete", rule)
}

// HostOnlyNet is one `list hostonlynets` entry — VirtualBox 7's vmnet-backed
// host-only NETWORK family (the host-only INTERFACE successor on macOS
// hosts; a different object from HostOnlyIf).
type HostOnlyNet struct {
	Name            string
	GUID            string
	NetworkMask     string
	LowerIP         string
	UpperIP         string
	VBoxNetworkName string
	Enabled         bool
}

// ListHostOnlyNets parses `VBoxManage list hostonlynets` — Key: value blocks
// per network (field spellings tolerant; unverifiable live on this
// codebase's own host, which carries none).
func ListHostOnlyNets(ctx context.Context, vboxManage string) ([]HostOnlyNet, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "hostonlynets")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list hostonlynets: %w", err)
	}

	nets := []HostOnlyNet{}
	var current *HostOnlyNet
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Name":
			nets = append(nets, HostOnlyNet{Name: value})
			current = &nets[len(nets)-1]
		case "GUID", "Id":
			if current != nil {
				current.GUID = value
			}
		case "State", "Enabled":
			if current != nil {
				current.Enabled = strings.EqualFold(value, "Enabled") || strings.EqualFold(value, "Yes")
			}
		case "NetworkMask", "Netmask":
			if current != nil {
				current.NetworkMask = value
			}
		case "LowerIP", "LowerIPAddress":
			if current != nil {
				current.LowerIP = value
			}
		case "UpperIP", "UpperIPAddress":
			if current != nil {
				current.UpperIP = value
			}
		case "VBoxNetworkName":
			if current != nil {
				current.VBoxNetworkName = value
			}
		}
	}
	return nets, nil
}

// HostOnlyNetOptions carries add/modify's knobs — zero/nil values skip the
// flag.
type HostOnlyNetOptions struct {
	Netmask string
	LowerIP string
	UpperIP string
	Enabled *bool
}

func hostOnlyNetFlags(opts HostOnlyNetOptions) []string {
	flags := []string{}
	if opts.Netmask != "" {
		flags = append(flags, "--netmask", opts.Netmask)
	}
	if opts.LowerIP != "" {
		flags = append(flags, "--lower-ip", opts.LowerIP)
	}
	if opts.UpperIP != "" {
		flags = append(flags, "--upper-ip", opts.UpperIP)
	}
	if opts.Enabled != nil {
		if *opts.Enabled {
			flags = append(flags, "--enable")
		} else {
			flags = append(flags, "--disable")
		}
	}
	return flags
}

// AddHostOnlyNet creates a host-only network (`hostonlynet add`).
func AddHostOnlyNet(ctx context.Context, vboxManage, name string, opts HostOnlyNetOptions) error {
	args := append([]string{"hostonlynet", "add", "--name", name}, hostOnlyNetFlags(opts)...)
	return runSimple(ctx, vboxManage, args...)
}

// ModifyHostOnlyNet converges an existing host-only network onto the set
// options.
func ModifyHostOnlyNet(ctx context.Context, vboxManage, name string, opts HostOnlyNetOptions) error {
	args := append([]string{"hostonlynet", "modify", "--name", name}, hostOnlyNetFlags(opts)...)
	return runSimple(ctx, vboxManage, args...)
}

// RemoveHostOnlyNet deletes a host-only network.
func RemoveHostOnlyNet(ctx context.Context, vboxManage, name string) error {
	return runSimple(ctx, vboxManage, "hostonlynet", "remove", "--name", name)
}
