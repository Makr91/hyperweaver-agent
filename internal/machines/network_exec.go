package machines

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The provisioning-network executors — zoneweaver's
// ProvisioningNetworkController setup/teardown chains (etherstub → host VNIC
// → static IP → NAT → forwarding → dhcpd) translated: VirtualBox's host-only
// interface IS the etherstub+VNIC+IP triple, its DHCP server IS dhcpd, and
// NAT/forwarding drop out (a host-only network reaches the host directly —
// all the pipeline needs). The base queues its pieces as chained children
// because its network task families exist independently; here the two
// operations run whole, serialized by the same category the base uses.

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
// callers fall back to the document's control IP.
func FindSSHForward(ctx context.Context, machine *Machine) int {
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
	if !network.Enabled {
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

// networkTeardown executes provisioning_network_teardown — the base's reverse
// order: DHCP first, then the interface. Absent components are simply noted.
func (e *executors) networkTeardown(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	network := e.env.Network
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
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
