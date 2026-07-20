package machines

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// UseHostOnlyNets reports Oracle's platform split (vagrant's
// use_host_only_nets? with the version check dropped — this agent's floor is
// VirtualBox 7): macOS removed host-only ADAPTERS and manages hostonlynet
// NETWORKS; every other host OS manages host-only interfaces and lacks the
// hostonlynet verbs entirely.
func UseHostOnlyNets() bool {
	return runtime.GOOS == "darwin"
}

// ProvisioningNetName is the darwin provisioning network's fixed name — the
// interface world lets VirtualBox assign names and finds by host IP; the
// hostonlynet world names networks, so ONE deterministic name is the
// identity.
const ProvisioningNetName = "hyperweaver-provision"

// FindProvisioningNet locates the darwin provisioning host-only NETWORK by
// its fixed name (FindProvisioningIf's hostonlynet twin). nil when absent.
func FindProvisioningNet(ctx context.Context, vboxExe string) (*vbox.HostOnlyNet, error) {
	nets, err := vbox.ListHostOnlyNets(ctx, vboxExe)
	if err != nil {
		return nil, err
	}
	for i := range nets {
		if nets[i].Name == ProvisioningNetName {
			return &nets[i], nil
		}
	}
	return nil, nil
}

// BridgeCandidates lists the host's bridgeable interfaces for the picker. On
// darwin (Oracle's split) hostonlynet families surface their vmnet BACKING
// bridges in bridgedifs too (bridge100-style entries carrying the network's
// own subnet — vagrant #13025's picker hole); those are EXCLUDED by subnet
// match. A failed hostonlynets read degrades to the unfiltered list.
func BridgeCandidates(ctx context.Context, vboxExe string) ([]vbox.BridgedIf, error) {
	interfaces, err := vbox.ListBridgedIfs(ctx, vboxExe)
	if err != nil {
		return nil, err
	}
	if !UseHostOnlyNets() {
		return interfaces, nil
	}
	nets, nerr := vbox.ListHostOnlyNets(ctx, vboxExe)
	if nerr != nil {
		nets = nil
	}
	if len(nets) == 0 {
		return interfaces, nil
	}
	filtered := make([]vbox.BridgedIf, 0, len(interfaces))
	for i := range interfaces {
		if hostOnlyNetBacking(&interfaces[i], nets) {
			continue
		}
		filtered = append(filtered, interfaces[i])
	}
	return filtered, nil
}

// hostOnlyNetBacking reports whether a bridgeable interface's address sits
// inside any hostonlynet's subnet — the vmnet backing-bridge signature.
func hostOnlyNetBacking(iface *vbox.BridgedIf, nets []vbox.HostOnlyNet) bool {
	ip := net.ParseIP(iface.IPAddress)
	if ip == nil {
		return false
	}
	for i := range nets {
		maskIP := net.ParseIP(nets[i].NetworkMask)
		lower := net.ParseIP(nets[i].LowerIP)
		if maskIP == nil || lower == nil {
			continue
		}
		mask4 := maskIP.To4()
		if mask4 == nil {
			continue
		}
		mask := net.IPMask(mask4)
		masked := ip.Mask(mask)
		if masked != nil && masked.Equal(lower.Mask(mask)) {
			return true
		}
	}
	return false
}

// The provisioning-network executors — zoneweaver's
// ProvisioningNetworkController setup/teardown chains (etherstub → host VNIC
// → static IP → NAT → forwarding → dhcpd) translated: VirtualBox's host-only
// interface IS the etherstub+VNIC+IP triple and its DHCP server IS dhcpd.
// The base's NAT/forwarding pieces (provisioning-NIC egress) translate to
// the NAT adapter pinned at create (adapter 1, ssh port-forward transport —
// Mark's architecture 2026-07-07), not to anything here; this host-only
// machinery stays dormant-but-available for host-type networks[] entries.
// The base queues its pieces as chained children because its network task
// families exist independently; here the two operations run whole,
// serialized by the same category the base uses.

// Provisioning-network operations (the base's exact names).
const (
	OpNetworkSetup    = "provisioning_network_setup"
	OpNetworkTeardown = "provisioning_network_teardown"
)

// NetworkEnv is the provisioning-network configuration the executors and the
// create chain consume (provisioning.network).
type NetworkEnv struct {
	Enabled        bool
	Subnet         string
	HostIP         string
	Netmask        string
	DHCPServerIP   string
	DHCPRangeStart string
	DHCPRangeEnd   string
}

// FindProvisioningIf locates the provisioning host-only interface by its
// host IP — the interface identity, since VirtualBox assigns names itself
// (the base's componentExists('vnic', name) check, keyed by address).
func FindProvisioningIf(ctx context.Context, vboxExe, hostIP string) (*vbox.HostOnlyIf, error) {
	interfaces, err := vbox.ListHostOnlyIfs(ctx, vboxExe)
	if err != nil {
		return nil, err
	}
	for i := range interfaces {
		if interfaces[i].IPAddress == hostIP {
			return &interfaces[i], nil
		}
	}
	return nil, nil
}

// FindProvisioningDHCP locates the interface's DHCP server by its
// VBoxNetworkName (the status endpoint and the setup executor share it).
func FindProvisioningDHCP(ctx context.Context, vboxExe, networkName string) (*vbox.DHCPServer, error) {
	servers, err := vbox.ListDHCPServers(ctx, vboxExe)
	if err != nil {
		return nil, err
	}
	for i := range servers {
		if servers[i].NetworkName == networkName {
			return &servers[i], nil
		}
	}
	return nil, nil
}

// FindSSHForward returns the host port of the machine's NAT ssh port-forward
// — the provisioning NIC's transport (Mark's architecture, 2026-07-07:
// adapter 1 IS the provisioning NIC; on VirtualBox the host reaches it
// through the forward, vagrant's model, so guest network reconfiguration can
// never kill the pipeline's session). 0 when the machine carries no rule —
// callers fall back to the document's control IP. utm machines answer from
// their emulated-interface forwards (create's ssh forward lives there —
// the only UTM interface mode whose forwards take effect).
func FindSSHForward(ctx context.Context, machine *Machine) int {
	if machine.Hypervisor == HypervisorUTM {
		if machine.UUID == nil || *machine.UUID == "" {
			return 0
		}
		forwards, err := utm.ReadForwardedPorts(ctx, *machine.UUID)
		if err != nil {
			return 0
		}
		for _, forward := range forwards {
			if forward.GuestPort == 22 && forward.HostPort > 0 {
				return forward.HostPort
			}
		}
		return 0
	}
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return 0
	}
	info, err := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget())
	if err != nil {
		return 0
	}
	for key, value := range info.Raw {
		if !strings.HasPrefix(key, "Forwarding(") {
			continue
		}
		// name,proto,hostip,hostport,guestip,guestport
		parts := strings.Split(value, ",")
		if len(parts) != 6 || parts[1] != "tcp" || parts[5] != "22" {
			continue
		}
		if port, perr := strconv.Atoi(parts[3]); perr == nil && port > 0 {
			return port
		}
	}
	return 0
}

// FindWinRMForward returns the host port of the machine's NAT winrm
// port-forward — FindSSHForward's winrm twin (zoneweaver's shipped winrm
// shape, sync 2026-07-17: W-Q1..W-Q5): the same Forwarding(N) parse, the
// rule NAMED "winrm" winning outright, any other tcp rule whose guest port
// matches the RULED guest winrm port (the document's winrm_port — no veto)
// serving as the fallback for pre-name forwards and hand-built machines.
// 0 when neither exists — callers fall back to the control IP with the
// ruled guest port.
func FindWinRMForward(ctx context.Context, machine *Machine, guestPort int) int {
	if machine.Hypervisor == HypervisorUTM {
		// winrm rides the VBox natpf shape only — utm machines answer 0.
		return 0
	}
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return 0
	}
	info, err := vbox.ShowVMInfo(ctx, vboxExe, machine.VBoxTarget())
	if err != nil {
		return 0
	}
	fallback := 0
	for key, value := range info.Raw {
		if !strings.HasPrefix(key, "Forwarding(") {
			continue
		}
		// name,proto,hostip,hostport,guestip,guestport
		parts := strings.Split(value, ",")
		if len(parts) != 6 || parts[1] != "tcp" {
			continue
		}
		port, perr := strconv.Atoi(parts[3])
		if perr != nil || port <= 0 {
			continue
		}
		if parts[0] == "winrm" {
			return port
		}
		if guestPort > 0 && parts[5] == strconv.Itoa(guestPort) {
			fallback = port
		}
	}
	return fallback
}

// removeDHCPLeases removes a machine's fixed-lease configs from the
// provisioning DHCP server — machine delete's cleanup, run BEFORE the VM
// unregisters (the individual config is keyed by VM and the --vm reference
// stops resolving after; without this the server accumulates stale entries,
// seen live in Mark's 7.2.8 dhcpservers listing). Every NIC slot is swept
// rather than computing positions from the stored document — the document's
// network list can drift from where leases were actually written (proven by
// the pre-adapter-shift machines). Misses are silent; removals narrate;
// absent components never fail the delete.
func (e *executors) removeDHCPLeases(ctx context.Context, vboxExe string, machine *Machine, out *tasks.OutputWriter) {
	network := e.env.Network
	if !network.Enabled || UseHostOnlyNets() {
		return
	}
	iface, err := FindProvisioningIf(ctx, vboxExe, network.HostIP)
	if err != nil || iface == nil {
		return
	}
	for nic := 1; nic <= maxNICSlots; nic++ {
		if rerr := vbox.RemoveDHCPVMConfig(ctx, vboxExe, iface.Name,
			machine.VBoxTarget(), nic); rerr == nil {
			out.Write("stdout", fmt.Sprintf("Removed DHCP fixed lease for NIC %d\n", nic))
		}
	}
}

// networkSetup executes provisioning_network_setup — the base's setup chain,
// idempotent at every component: the interface is created only when no
// host-only interface carries the configured host IP, its address always
// converges onto the configuration, and the DHCP server is added or modified
// to match.
func (e *executors) networkSetup(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	network := e.env.Network
	if !network.Enabled {
		return errors.New("provisioning network is disabled in configuration (provisioning.network.enabled)")
	}
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}
	if UseHostOnlyNets() {
		return e.networkSetupDarwin(ctx, task, vboxExe, out)
	}

	e.taskProgress(task, 10, "resolving_interface")
	iface, err := FindProvisioningIf(ctx, vboxExe, network.HostIP)
	if err != nil {
		return err
	}
	if iface == nil {
		e.taskProgress(task, 25, "creating_interface")
		out.Write("stdout", "Creating host-only interface for "+network.HostIP+"\n")
		name, cerr := vbox.CreateHostOnlyIf(ctx, vboxExe)
		if cerr != nil {
			return cerr
		}
		out.Write("stdout", "VirtualBox assigned interface "+name+"\n")
		iface = &vbox.HostOnlyIf{Name: name}
	} else {
		out.Write("stdout", "Host-only interface exists: "+iface.Name+"\n")
	}

	e.taskProgress(task, 45, "configuring_address")
	if cerr := vbox.ConfigureHostOnlyIf(ctx, vboxExe, iface.Name, network.HostIP, network.Netmask); cerr != nil {
		return cerr
	}

	// Re-list for the interface's VBoxNetworkName — the DHCP server's key
	// (a just-created interface was built without one in hand).
	refreshed, err := FindProvisioningIf(ctx, vboxExe, network.HostIP)
	if err != nil {
		return err
	}
	if refreshed == nil {
		return fmt.Errorf("interface %s did not take address %s", iface.Name, network.HostIP)
	}

	e.taskProgress(task, 70, "configuring_dhcp")
	server, err := FindProvisioningDHCP(ctx, vboxExe, refreshed.VBoxNetworkName)
	if err != nil {
		return err
	}
	if server == nil {
		out.Write("stdout", fmt.Sprintf("Adding DHCP server %s (%s - %s)\n",
			network.DHCPServerIP, network.DHCPRangeStart, network.DHCPRangeEnd))
		if aerr := vbox.AddDHCPServer(ctx, vboxExe, refreshed.Name, network.DHCPServerIP,
			network.Netmask, network.DHCPRangeStart, network.DHCPRangeEnd); aerr != nil {
			return aerr
		}
	} else {
		out.Write("stdout", "Converging existing DHCP server onto the configuration\n")
		if merr := vbox.ModifyDHCPServer(ctx, vboxExe, refreshed.Name, network.DHCPServerIP,
			network.Netmask, network.DHCPRangeStart, network.DHCPRangeEnd); merr != nil {
			return merr
		}
	}

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Provisioning network ready: "+refreshed.Name+" ("+network.Subnet+")\n")
	return nil
}

// networkSetupDarwin is setup's hostonlynet half (Oracle's macOS split —
// vagrant's create_host_only_network model): ONE named network whose embedded
// LowerIP-UpperIP range IS the DHCP (no dhcpserver verbs exist in this
// family), converged idempotently onto the configured range. The host side's
// own address is vmnet's to assign — provisioning.network.host_ip has no
// write path here, and the pipeline's transport rides the NAT forward
// regardless.
func (e *executors) networkSetupDarwin(ctx context.Context, task *tasks.Task, vboxExe string, out *tasks.OutputWriter) error {
	network := e.env.Network
	e.taskProgress(task, 20, "resolving_network")
	existing, err := FindProvisioningNet(ctx, vboxExe)
	if err != nil {
		return err
	}
	enabled := true
	opts := vbox.HostOnlyNetOptions{
		Netmask: network.Netmask,
		LowerIP: network.DHCPRangeStart,
		UpperIP: network.DHCPRangeEnd,
		Enabled: &enabled,
	}
	if existing == nil {
		e.taskProgress(task, 50, "creating_network")
		out.Write("stdout", "Creating host-only network "+ProvisioningNetName+
			" ("+network.DHCPRangeStart+" - "+network.DHCPRangeEnd+")\n")
		if aerr := vbox.AddHostOnlyNet(ctx, vboxExe, ProvisioningNetName, opts); aerr != nil {
			return aerr
		}
	} else {
		e.taskProgress(task, 50, "converging_network")
		out.Write("stdout", "Converging host-only network "+ProvisioningNetName+" onto the configuration\n")
		if merr := vbox.ModifyHostOnlyNet(ctx, vboxExe, ProvisioningNetName, opts); merr != nil {
			return merr
		}
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Provisioning network ready: "+ProvisioningNetName+" ("+network.Subnet+
		") — the embedded range serves DHCP; per-VM fixed leases have no hostonlynet analog\n")
	return nil
}

// networkTeardown executes provisioning_network_teardown — the base's reverse
// order: DHCP first, then the interface. Absent components are simply noted.
func (e *executors) networkTeardown(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	network := e.env.Network
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}
	if UseHostOnlyNets() {
		e.taskProgress(task, 20, "resolving_network")
		existing, err := FindProvisioningNet(ctx, vboxExe)
		if err != nil {
			return err
		}
		if existing == nil {
			e.taskProgress(task, 100, "completed")
			out.Write("stdout", "No host-only network named "+ProvisioningNetName+" — nothing to tear down\n")
			return nil
		}
		e.taskProgress(task, 70, "removing_network")
		if rerr := vbox.RemoveHostOnlyNet(ctx, vboxExe, ProvisioningNetName); rerr != nil {
			return rerr
		}
		e.taskProgress(task, 100, "completed")
		out.Write("stdout", "Provisioning network removed ("+ProvisioningNetName+")\n")
		return nil
	}

	e.taskProgress(task, 10, "resolving_interface")
	iface, err := FindProvisioningIf(ctx, vboxExe, network.HostIP)
	if err != nil {
		return err
	}
	if iface == nil {
		e.taskProgress(task, 100, "completed")
		out.Write("stdout", "No host-only interface carries "+network.HostIP+" — nothing to tear down\n")
		return nil
	}

	e.taskProgress(task, 40, "removing_dhcp")
	if rerr := vbox.RemoveDHCPServer(ctx, vboxExe, iface.Name); rerr != nil {
		out.Write("stderr", "DHCP server removal: "+rerr.Error()+" (continuing)\n")
	}

	e.taskProgress(task, 70, "removing_interface")
	if rerr := vbox.RemoveHostOnlyIf(ctx, vboxExe, iface.Name); rerr != nil {
		return rerr
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Provisioning network removed ("+iface.Name+")\n")
	return nil
}
