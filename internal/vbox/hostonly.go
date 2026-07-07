package vbox

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Host-only networking verbs — the provisioning network's hypervisor layer
// (zoneweaver's etherstub + host VNIC + static IP + dhcpd, spoken in
// VBoxManage per the 7.2.8 usage: `hostonlyif create|ipconfig|remove`,
// `dhcpserver add|modify|remove`, `list hostonlyifs|dhcpservers`). VirtualBox
// collapses the base's etherstub+VNIC+IP triple into ONE host-only interface,
// and its DHCP server carries the base's dhcpd.conf host blocks as per-VM
// fixed-address configs (--vm/--nic scope — no MAC read-back needed).

// HostOnlyIf is one `list hostonlyifs` entry (the fields the provisioning
// network consumes).
type HostOnlyIf struct {
	Name            string
	IPAddress       string
	NetworkMask     string
	VBoxNetworkName string
}

// ListHostOnlyIfs parses `VBoxManage list hostonlyifs` — blocks of
// `Key: value` lines, each starting at a Name: line.
func ListHostOnlyIfs(ctx context.Context, vboxManage string) ([]HostOnlyIf, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "hostonlyifs")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list hostonlyifs: %w", err)
	}

	interfaces := []HostOnlyIf{}
	var current *HostOnlyIf
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Name":
			interfaces = append(interfaces, HostOnlyIf{Name: value})
			current = &interfaces[len(interfaces)-1]
		case "IPAddress":
			if current != nil {
				current.IPAddress = value
			}
		case "NetworkMask":
			if current != nil {
				current.NetworkMask = value
			}
		case "VBoxNetworkName":
			if current != nil {
				current.VBoxNetworkName = value
			}
		}
	}
	return interfaces, nil
}

// createdIfPattern extracts the assigned name from `hostonlyif create`'s
// "Interface 'X' was successfully created" output.
var createdIfPattern = regexp.MustCompile(`Interface '(.+)' was successfully created`)

// CreateHostOnlyIf creates a host-only interface and returns the name
// VirtualBox assigned it (names are VirtualBox's own — never configurable).
func CreateHostOnlyIf(ctx context.Context, vboxManage string) (string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "hostonlyif", "create")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("VBoxManage hostonlyif create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	match := createdIfPattern.FindStringSubmatch(string(out))
	if match == nil {
		return "", errors.New("hostonlyif create succeeded but reported no interface name: " + strings.TrimSpace(string(out)))
	}
	return match[1], nil
}

// ConfigureHostOnlyIf assigns the interface its static IPv4 address (the
// base's create_ip_address — `hostonlyif ipconfig <ifname> --ip --netmask`).
func ConfigureHostOnlyIf(ctx context.Context, vboxManage, name, ip, netmask string) error {
	return runSimple(ctx, vboxManage, "hostonlyif", "ipconfig", name,
		"--ip="+ip, "--netmask="+netmask)
}

// RemoveHostOnlyIf deletes a host-only interface (teardown's delete_vnic +
// delete_etherstub in one).
func RemoveHostOnlyIf(ctx context.Context, vboxManage, name string) error {
	return runSimple(ctx, vboxManage, "hostonlyif", "remove", name)
}

// DHCPServer is one `list dhcpservers` entry.
type DHCPServer struct {
	NetworkName string
	ServerIP    string
	LowerIP     string
	UpperIP     string
	NetworkMask string
	Enabled     bool
}

// ListDHCPServers parses `VBoxManage list dhcpservers` — blocks starting at a
// NetworkName: line; nested configuration lines carry keys outside this set.
func ListDHCPServers(ctx context.Context, vboxManage string) ([]DHCPServer, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "dhcpservers")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list dhcpservers: %w", err)
	}

	servers := []DHCPServer{}
	var current *DHCPServer
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "NetworkName":
			servers = append(servers, DHCPServer{NetworkName: value})
			current = &servers[len(servers)-1]
		case "Dhcpd IP":
			if current != nil {
				current.ServerIP = value
			}
		case "LowerIPAddress":
			if current != nil {
				current.LowerIP = value
			}
		case "UpperIPAddress":
			if current != nil {
				current.UpperIP = value
			}
		case "NetworkMask":
			if current != nil && current.NetworkMask == "" {
				current.NetworkMask = value
			}
		case "Enabled":
			if current != nil {
				current.Enabled = strings.EqualFold(value, "Yes")
			}
		}
	}
	return servers, nil
}

// AddDHCPServer creates the interface's DHCP server (the base's
// dhcp_update_config): subnet range + its own server address, enabled.
func AddDHCPServer(ctx context.Context, vboxManage, ifname, serverIP, netmask, lowerIP, upperIP string) error {
	return runSimple(ctx, vboxManage, "dhcpserver", "add",
		"--interface="+ifname, "--server-ip="+serverIP, "--netmask="+netmask,
		"--lower-ip="+lowerIP, "--upper-ip="+upperIP, "--enable")
}

// ModifyDHCPServer converges an existing DHCP server onto the configured
// values (setup's idempotent re-run).
func ModifyDHCPServer(ctx context.Context, vboxManage, ifname, serverIP, netmask, lowerIP, upperIP string) error {
	return runSimple(ctx, vboxManage, "dhcpserver", "modify",
		"--interface="+ifname, "--server-ip="+serverIP, "--netmask="+netmask,
		"--lower-ip="+lowerIP, "--upper-ip="+upperIP, "--enable")
}

// RemoveDHCPServer deletes the interface's DHCP server (teardown's
// dhcp_service_control stop).
func RemoveDHCPServer(ctx context.Context, vboxManage, ifname string) error {
	return runSimple(ctx, vboxManage, "dhcpserver", "remove", "--interface="+ifname)
}

// SetDHCPFixedAddress pins one VM NIC's DHCP answer to an address (the base's
// dhcp_add_host host block, keyed by VM+NIC instead of MAC — the 7.2
// per-config scope `--vm --nic --fixed-address`). The guest's ordinary DHCP
// request then receives the document's own control IP.
func SetDHCPFixedAddress(ctx context.Context, vboxManage, ifname, vm string, nic int, address string) error {
	return runSimple(ctx, vboxManage, "dhcpserver", "modify",
		"--interface="+ifname,
		"--vm="+vm, "--nic="+strconv.Itoa(nic), "--fixed-address="+address)
}

// RemoveDHCPVMConfig deletes one VM NIC's individual DHCP config (the 7.2
// `--vm --nic --remove-config` scope) — machine delete's lease cleanup; the
// config is keyed by VM and turns stale the moment the VM unregisters.
func RemoveDHCPVMConfig(ctx context.Context, vboxManage, ifname, vm string, nic int) error {
	return runSimple(ctx, vboxManage, "dhcpserver", "modify",
		"--interface="+ifname,
		"--vm="+vm, "--nic="+strconv.Itoa(nic), "--remove-config")
}

// RestartDHCPServer restarts the interface's DHCP server process (the base's
// dhcp_service_control restart after dhcpd.conf writes). A running
// VBoxNetDHCP never re-reads its configuration, so every fixed-lease write
// must be followed by a restart to take effect (runtime-proven 2026-07-07).
func RestartDHCPServer(ctx context.Context, vboxManage, ifname string) error {
	return runSimple(ctx, vboxManage, "dhcpserver", "restart", "--interface="+ifname)
}
