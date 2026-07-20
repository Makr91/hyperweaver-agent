package machines

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/sslcert"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// createConfig executes machine_create_config: createvm + the full Hosts.rb
// VirtualBox directive set + storage attach + NICs + cloud-init properties.
// Failure unregisters the half-made machine (the base's zonecfg delete -F).
func (e *executors) createConfig(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	output, err := e.dependencyOutput(ctx, task)
	if err != nil {
		return err
	}
	if meta.Spec.Hypervisor == HypervisorUTM {
		return e.createConfigUTM(ctx, task, meta.Spec, output, out)
	}
	document := parseConfigBytes(output.Document)
	settings := document.Section("settings")

	// consoleport guard at the RENDERED document (converged, sync 2026-07-17):
	// the 0.1.31 package defaults consoleport to server_id, which the HTTP
	// pre-flight never sees — packaged creates render in the task chain. An
	// out-of-range or non-numeric value fails HERE, before createvm/modifyvm,
	// instead of surfacing as VRDE's cryptic mid-chain E_INVALIDARG. An absent
	// consoleport stays exactly as before (no VRDE flags, no invented default).
	if value, ok := settings["consoleport"]; ok {
		if problem := ConsolePortProblem(value); problem != "" {
			out.Write("stderr", "Rendered document carries consoleport "+
				stringOr(value, fmt.Sprint(value))+": "+problem+"\n")
			return errors.New(problem)
		}
	}
	// vcpus guard at the RENDERED document (converged, sync 2026-07-17 —
	// zoneweaver's proposal, ACKED): a present vcpus must be a whole number
	// >= 1 (the 0.1.31 template renders integral floats like 2.0 — those
	// pass); anything else fails HERE, before createvm/modifyvm. An absent
	// vcpus keeps the existing default-2 behavior byte-identical.
	if value, ok := settings["vcpus"]; ok {
		if problem := VCPUProblem(value); problem != "" {
			out.Write("stderr", "Rendered document carries vcpus "+
				stringOr(value, fmt.Sprint(value))+": "+problem+"\n")
			return errors.New(problem)
		}
	}

	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	e.taskProgress(task, 20, "creating_vm")
	e.clearStaleSettings(ctx, vboxExe, task.MachineName, out)
	arch := "x86"
	if strings.Contains(stringOr(settings["box_arch"], "amd64"), "arm") {
		arch = "arm"
	}
	uuid, err := vbox.CreateVM(ctx, vboxExe, task.MachineName, arch,
		stringOr(settings["os_type"], "Debian_64"), e.env.MachinesDir)
	if err != nil {
		return err
	}
	failed := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — unregistering the half-made machine\n")
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if uerr := vbox.UnregisterVM(cleanupCtx, vboxExe, task.MachineName, false); uerr != nil {
			out.Write("stderr", "Unregister failed: "+uerr.Error()+"\n")
		}
		e.clearStaleSettings(cleanupCtx, vboxExe, task.MachineName, out)
		return ferr
	}

	// Host-type NICs ride the provisioning network's host-only interface —
	// resolved by host IP (VirtualBox names interfaces itself); absent setup
	// is a loud note, never an invented adapter. On macOS (Oracle's split)
	// the target is the hostonlynet NETWORK, resolved by its fixed name.
	hostAdapter := ""
	if e.env.Network.Enabled && hasHostNetworks(document) {
		switch {
		case UseHostOnlyNets():
			if provNet, ferr := FindProvisioningNet(ctx, vboxExe); ferr == nil && provNet != nil {
				hostAdapter = provNet.Name
			} else {
				out.Write("stderr", "Provisioning network is not set up — host-type NICs attach without a network (run POST /provisioning/network/setup first)\n")
			}
		default:
			if iface, ferr := FindProvisioningIf(ctx, vboxExe, e.env.Network.HostIP); ferr == nil && iface != nil {
				hostAdapter = iface.Name
			} else {
				out.Write("stderr", "Provisioning network is not set up — host-type NICs attach without an adapter (run POST /provisioning/network/setup first)\n")
			}
		}
	}

	// The provisioning NIC's transport (Mark's architecture, 2026-07-07):
	// adapter 1 is the provisioning NIC — on VirtualBox that is the NAT
	// adapter, and the host reaches the guest through an ssh port-forward
	// (vagrant's model). The pipeline dials 127.0.0.1:<port>, never a real
	// adapter, so the networking role can reconfigure every guest interface
	// without ever killing the session carrying it.
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return failed("ssh port-forward allocation", perr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))

	// winrm communicator (zoneweaver's shipped winrm shape, sync 2026-07-17:
	// W-Q1..W-Q5): a SECOND natpf1 forward beside the ssh one — the pipeline
	// dials 127.0.0.1:<forward> for winrm exactly like it does for ssh. The
	// document's winrm_port names the GUEST port (ruled, no veto).
	winrmForwardPort := 0
	if winrm, _ := ExtractWinRM(settings); winrm.Enabled {
		port, werr := allocateLocalPort(ctx)
		if werr != nil {
			return failed("winrm port-forward allocation", werr)
		}
		winrmForwardPort = port
		out.Write("stdout", fmt.Sprintf("Provisioning WinRM port-forward: 127.0.0.1:%d → guest %d\n",
			winrmForwardPort, winrm.Port))
	}

	e.taskProgress(task, 40, "configuring_vm")
	flags, ferr := modifyFlags(document, hostAdapter, sshPort, winrmForwardPort)
	if ferr != nil {
		return failed("modifyvm", ferr)
	}
	// The QEMU guest-agent UART: COM2 onto a host pipe — the credential-less
	// guest channel the box templates' qemu-ga answers on. A PER-MACHINE
	// create option (Mark's Proxmox-model ruling 2026-07-12, zoneweaver's
	// shipped decision ported: zones.guest_agent === true, default OFF, under
	// the guest_agent.enabled master gate — ConfigurationManager.js's
	// buildExtraAttrCommand). A document claiming serial port 2 itself wins;
	// QGA steps aside. Opt-in later via POST /machines/{name}/guest-agent/setup.
	if e.env.GuestAgentEnabled && onOff(document.Section("vbox")["guest_agent"]) == "on" {
		if serialPortClaimed(document.Section("vbox"), 2) {
			out.Write("stderr", "Document claims serial port 2 — guest-agent UART skipped\n")
		} else {
			pipe := qga.PipePath(e.machineWorkdir(task.MachineName), task.MachineName)
			flags = append(flags, "--uart2", "0x2F8", "3", "--uart-mode2", "server", pipe)
			out.Write("stdout", "Guest-agent channel: COM2 → "+pipe+"\n")
		}
	}
	// VRDE TLS from birth (Mark's zero-click ruling 2026-07-11): mint the
	// machine's certificate from the agent CA and set the Enhanced-security
	// properties with the other create flags — every new machine is
	// browser-RDP-ready without the vrde-tls setup. PREPENDED so document
	// knobs override (modifyvm's last occurrence wins). Failure only
	// narrates — the bridge self-heals live at first connect anyway.
	if e.env.VRDECertRoot != "" {
		certPath, keyPath, caPath, verr := sslcert.EnsureVRDECertificate(
			e.env.CACertPath, e.env.CAKeyPath,
			filepath.Join(e.env.VRDECertRoot, task.MachineName), task.MachineName)
		if verr != nil {
			out.Write("stderr", "VRDE TLS material generation failed (the browser-RDP bridge self-heals at first connect): "+verr.Error()+"\n")
		} else {
			flags = append([]string{
				"--vrde-property=Security/Method=Negotiate",
				"--vrde-property=Security/ServerCertificate=" + certPath,
				"--vrde-property=Security/ServerPrivateKey=" + keyPath,
				"--vrde-property=Security/CACertificate=" + caPath,
			}, flags...)
			out.Write("stdout", "VRDE TLS: certificate minted, Enhanced security set — browser-RDP ready from birth\n")
		}
	}
	if merr := vbox.ModifyVM(ctx, vboxExe, task.MachineName, flags); merr != nil {
		return failed("modifyvm", merr)
	}

	// Pin each host-network address as a DHCP fixed lease (the base's
	// dhcp_add_host block): the guest's ordinary DHCP request then receives
	// the document's own control IP — the deterministic addressing wait_ssh
	// dials. hostonlynet (macOS) embeds ONE range and has no per-VM lease
	// verbs — pinned addresses narrate honestly there (the networking role
	// pins them in-guest, and the pipeline's transport is the NAT forward).
	if hostAdapter != "" && UseHostOnlyNets() {
		for i, entry := range document.List("networks") {
			network := mapOr(entry)
			if stringOr(network["type"], "") != "host" {
				continue
			}
			if address := stringOr(network["address"], ""); address != "" {
				out.Write("stdout", fmt.Sprintf(
					"NIC %d address %s: hostonlynet embeds one DHCP range — per-VM fixed leases have no macOS analog; the networking role pins the address in-guest\n",
					i+2, address))
			}
		}
	}
	if hostAdapter != "" && !UseHostOnlyNets() {
		leases := 0
		for i, entry := range document.List("networks") {
			network := mapOr(entry)
			if stringOr(network["type"], "") != "host" {
				continue
			}
			address := stringOr(network["address"], "")
			if address == "" {
				continue
			}
			// NIC numbering follows the adapter shift: NAT at 1, this
			// document network at adapter i+2.
			if lerr := vbox.SetDHCPFixedAddress(ctx, vboxExe, hostAdapter,
				task.MachineName, i+2, address); lerr != nil {
				return failed("dhcp fixed lease", lerr)
			}
			out.Write("stdout", fmt.Sprintf("Fixed DHCP lease: NIC %d → %s\n", i+2, address))
			leases++
		}
		// A running VBoxNetDHCP never re-reads its configuration
		// (runtime-proven 2026-07-07: hwtest-03's registered lease was
		// ignored — the guest drew the range start — until `dhcpserver
		// restart`). No process yet refuses the restart; that is fine, the
		// first boot starts it with fresh config.
		if leases > 0 {
			if rerr := vbox.RestartDHCPServer(ctx, vboxExe, hostAdapter); rerr != nil {
				out.Write("stdout", "DHCP server restart skipped (not running yet)\n")
			} else {
				out.Write("stdout", "DHCP server restarted — fixed leases active\n")
			}
		}
	}

	e.taskProgress(task, 60, "attaching_storage")
	if serr := e.attachStorage(ctx, vboxExe, task.MachineName, document, output, out); serr != nil {
		return failed("storage attach", serr)
	}

	e.taskProgress(task, 80, "configuring_cloud_init")
	for key, value := range mapOr(document["cloud_init"]) {
		if s := stringOr(value, ""); s != "" {
			if perr := vbox.SetGuestProperty(ctx, vboxExe, task.MachineName,
				"/Hyperweaver/CloudInit/"+key, s); perr != nil {
				out.Write("stderr", "cloud-init property "+key+": "+perr.Error()+"\n")
			}
		}
	}

	output.UUID = uuid
	if rerr := e.recordOutput(ctx, task, meta.Spec, output); rerr != nil {
		return failed("record output", rerr)
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" configured ("+uuid+")\n")
	return nil
}

// createConfigUTM is machine_create_config's UTM branch — the createvm/
// modifyvm flow spoken as bundle import + scripted configuration: utm.Import
// brings the storage child's box.utm bundle in whole, then Customize
// (name/cpus/memory/notes), a fresh MAC on NIC 0 (UTM cannot generate one),
// the provisioning ssh port-forward on the box's EMULATED interface (the
// only mode whose forwards take effect), document networks as vmnet QEMU
// args from net2, and the document's utm.qemu_args[] passthrough. The
// VBox-only mechanisms (DHCP fixed leases, VRDE TLS, guest-agent UART,
// cloud-init guestproperties, consoleport) have no analog here and are never
// called.
func (e *executors) createConfigUTM(ctx context.Context, task *tasks.Task, spec *Spec,
	output *createExecutionOutput, out *tasks.OutputWriter,
) error {
	document := parseConfigBytes(output.Document)
	settings := document.Section("settings")
	utmSection := document.Section("utm")
	bundlePath := output.BootdiskPath
	if bundlePath == "" {
		return errors.New("storage step recorded no box.utm bundle path")
	}

	e.taskProgress(task, 20, "importing_machine")
	out.Write("stdout", "Importing "+bundlePath+" into UTM\n")
	id, err := utm.Import(ctx, bundlePath)
	if err != nil {
		return err
	}
	// Failure past this point cannot clean up after itself: utmctl delete
	// needs the utmctl path, whose plumbing arrives with the lifecycle phase
	// — the leftover is narrated honestly instead.
	failed := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — imported machine "+id+
			" left in UTM — delete it in the UTM UI\n")
		return ferr
	}

	e.taskProgress(task, 40, "configuring_vm")
	if cerr := utm.Customize(ctx, id, utm.CustomizeOptions{
		Name:     task.MachineName,
		CPUs:     int(VCPUCount(settings["vcpus"], 2)),
		MemoryMB: int(memoryToMB(settings["memory"])),
		Notes:    stringOr(utmSection["notes"], ""),
	}); cerr != nil {
		return failed("customize", cerr)
	}
	if merr := utm.SetMACAddress(ctx, id, 0, utm.RandomMAC()); merr != nil {
		return failed("mac address", merr)
	}

	// The provisioning ssh transport rides the FIRST emulated interface —
	// port forwards function on no other mode; a box without one cannot carry
	// the transport, so the create refuses instead of inventing adapters.
	nics, nerr := utm.ReadNetworkInterfaces(ctx, id)
	if nerr != nil {
		return failed("read network interfaces", nerr)
	}
	emulatedIndex := -1
	for index, mode := range nics {
		if mode == "emulated" && (emulatedIndex < 0 || index < emulatedIndex) {
			emulatedIndex = index
		}
	}
	if emulatedIndex < 0 {
		return failed("network interfaces", errors.New("box "+
			stringOr(settings["box"], bundlePath)+
			" has no emulated network interface — port forwards need one"))
	}
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return failed("ssh port-forward allocation", perr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))
	if ferr := utm.AddPortForwards(ctx, id, emulatedIndex, []utm.ForwardedPort{{
		Protocol: "tcp", GuestPort: 22, HostIP: "127.0.0.1", HostPort: sshPort,
	}}); ferr != nil {
		return failed("ssh port-forward", ferr)
	}

	// Document networks ride as vmnet QEMU args from net2 (net0/net1 are the
	// box's shared+emulated base pair): host → vmnet-host, anything else →
	// vmnet-bridged with ifname from the entry's bridge. The document's
	// utm.qemu_args[] passthrough appends after them — the user's final word.
	qemuArgs := []string{}
	for i, entry := range document.List("networks") {
		network := mapOr(entry)
		netID := "net" + strconv.Itoa(i+2)
		netdev := "-netdev vmnet-bridged,id=" + netID
		if stringOr(network["type"], "external") == "host" {
			netdev = "-netdev vmnet-host,id=" + netID
		} else if bridge := stringOr(network["bridge"], ""); bridge != "" {
			netdev += ",ifname=" + bridge
		}
		mac := stringOr(network["mac"], "")
		if mac == "" || strings.EqualFold(mac, "auto") {
			mac = utm.RandomMAC()
		}
		qemuArgs = append(qemuArgs, netdev, "-device virtio-net-pci,mac="+mac+",netdev="+netID)
	}
	for _, entry := range listOr(utmSection["qemu_args"]) {
		if arg := stringOr(entry, ""); arg != "" {
			qemuArgs = append(qemuArgs, arg)
		}
	}
	if len(qemuArgs) > 0 {
		e.taskProgress(task, 70, "configuring_networks")
		if qerr := utm.AddQemuArgs(ctx, id, qemuArgs); qerr != nil {
			return failed("qemu args", qerr)
		}
	}

	output.UUID = id
	if rerr := e.recordOutput(ctx, task, spec, output); rerr != nil {
		return failed("record output", rerr)
	}
	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" configured ("+id+")\n")
	return nil
}

// allocateLocalPort reserves a free localhost TCP port for the ssh
// port-forward (bind :0, read the assignment, release).
func allocateLocalPort(ctx context.Context) (int, error) {
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port, nil
}

// hasHostNetworks reports whether the document declares any host-type
// network (the provisioning-network riders).
func hasHostNetworks(document MachineConfig) bool {
	for _, entry := range document.List("networks") {
		if stringOr(mapOr(entry)["type"], "") == "host" {
			return true
		}
	}
	return false
}
