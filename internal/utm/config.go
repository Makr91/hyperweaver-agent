package utm

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Configuration verbs over UTM's AppleScript API — every one edits the
// stored config and saves it with `update configuration`, so the machine
// must be stopped (the accrue-changes contract's apply point).

//go:embed scripts/customize_vm.applescript
var customizeVMScript []byte

//go:embed scripts/read_network_interfaces.applescript
var readNetworkInterfacesScript []byte

//go:embed scripts/read_forwarded_ports.applescript
var readForwardedPortsScript []byte

//go:embed scripts/add_port_forwards.applescript
var addPortForwardsScript []byte

//go:embed scripts/clear_port_forwards.applescript
var clearPortForwardsScript []byte

//go:embed scripts/add_qemu_args.applescript
var addQemuArgsScript []byte

//go:embed scripts/remove_qemu_args.applescript
var removeQemuArgsScript []byte

//go:embed scripts/read_qemu_args.applescript
var readQemuArgsScript []byte

//go:embed scripts/set_mac_address.applescript
var setMACAddressScript []byte

//go:embed scripts/add_registry_paths.applescript
var addRegistryPathsScript []byte

// CustomizeOptions carries the config properties Customize applies — zero
// values are skipped, so one call sets any subset.
type CustomizeOptions struct {
	Name     string
	CPUs     int
	MemoryMB int
	Notes    string
	// DirectoryShareMode is none, webDAV, or virtFS — translated to UTM's
	// 4-byte enum codes (SmOf|SmWv|SmVs) for the script.
	DirectoryShareMode string
}

var shareModeCodes = map[string]string{
	"none":   "SmOf",
	"webDAV": "SmWv",
	"virtFS": "SmVs",
}

// Customize applies the set fields of opts to a machine's configuration in
// one script pass.
func Customize(ctx context.Context, id string, opts CustomizeOptions) error {
	args := []string{id}
	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	if opts.MemoryMB > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.MemoryMB))
	}
	if opts.Notes != "" {
		args = append(args, "--notes", opts.Notes)
	}
	if opts.DirectoryShareMode != "" {
		code, ok := shareModeCodes[opts.DirectoryShareMode]
		if !ok {
			return fmt.Errorf("UTM customize: unknown directory share mode %q", opts.DirectoryShareMode)
		}
		// The 4-char code travels as a plain string — the form the vagrant_utm
		// plugin ships and runs live. Unverified on this codebase's own live
		// Mac: if UTM refuses string→enum coercion, the script needs
		// «constant ****SmOf»-style chevron constants instead.
		args = append(args, "--share-mode", code)
	}
	if len(args) == 1 {
		return nil
	}
	_, err := runOSA(ctx, customizeVMScript, "AppleScript", args...)
	return err
}

var nicLine = regexp.MustCompile(`^nic(\d+),(.+)$`)

// ReadNetworkInterfaces returns interface index → mode (shared | emulated |
// bridged | host | ...) from the machine's configuration.
func ReadNetworkInterfaces(ctx context.Context, id string) (map[int]string, error) {
	out, err := runOSA(ctx, readNetworkInterfacesScript, "AppleScript", id)
	if err != nil {
		return nil, err
	}
	nics := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		match := nicLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		if idx, perr := strconv.Atoi(match[1]); perr == nil {
			nics[idx] = strings.TrimSpace(match[2])
		}
	}
	return nics, nil
}

// ForwardedPort is one port-forward record on a machine's emulated
// interface.
type ForwardedPort struct {
	NIC       int    `json:"nic"`
	Protocol  string `json:"protocol"`
	GuestIP   string `json:"guest_ip,omitempty"`
	GuestPort int    `json:"guest_port"`
	HostIP    string `json:"host_ip,omitempty"`
	HostPort  int    `json:"host_port"`
}

// forwardingLine matches the read script's VirtualBox-style
// Forwarding(nic)(rule)="protocol,guestAddr,guestPort,hostAddr,hostPort"
// lines.
var forwardingLine = regexp.MustCompile(`^Forwarding\((\d+)\)\((\d+)\)="([^,]*),([^,]*),([^,]*),([^,]*),([^"]*)"$`)

// ReadForwardedPorts returns the machine's port forwards (emulated interface
// only — the sole mode whose forwards take effect).
func ReadForwardedPorts(ctx context.Context, id string) ([]ForwardedPort, error) {
	out, err := runOSA(ctx, readForwardedPortsScript, "AppleScript", id)
	if err != nil {
		return nil, err
	}
	forwards := []ForwardedPort{}
	for _, line := range strings.Split(out, "\n") {
		match := forwardingLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		nic, nicErr := strconv.Atoi(match[1])
		guestPort, guestErr := strconv.Atoi(match[5])
		hostPort, hostErr := strconv.Atoi(match[7])
		if nicErr != nil || guestErr != nil || hostErr != nil {
			continue
		}
		forwards = append(forwards, ForwardedPort{
			NIC:       nic,
			Protocol:  protocolName(match[3]),
			GuestIP:   match[4],
			GuestPort: guestPort,
			HostIP:    match[6],
			HostPort:  hostPort,
		})
	}
	return forwards, nil
}

// protocolName folds UTM's protocol enum (as the script's log coerces it)
// back to the agent's tcp/udp vocabulary.
func protocolName(code string) string {
	switch code {
	case "TcPp":
		return "tcp"
	case "UdPp":
		return "udp"
	}
	return strings.ToLower(code)
}

// protocolCode maps tcp/udp ("" defaults to tcp) to UTM's 4-byte protocol
// enums; anything else is refused.
func protocolCode(protocol string) (string, error) {
	switch strings.ToLower(protocol) {
	case "", "tcp":
		return "TcPp", nil
	case "udp":
		return "UdPp", nil
	}
	return "", fmt.Errorf("UTM port forward: unsupported protocol %q", protocol)
}

// AddPortForwards appends forwards to the interface at nicIndex — which must
// be the emulated interface for the rules to take effect.
func AddPortForwards(ctx context.Context, id string, nicIndex int, forwards []ForwardedPort) error {
	if len(forwards) == 0 {
		return nil
	}
	args := []string{id}
	for _, fw := range forwards {
		code, err := protocolCode(fw.Protocol)
		if err != nil {
			return err
		}
		rule := fmt.Sprintf("%s,%s,%d,%s,%d", code, fw.GuestIP, fw.GuestPort, fw.HostIP, fw.HostPort)
		args = append(args, "--index", strconv.Itoa(nicIndex), rule)
	}
	_, err := runOSA(ctx, addPortForwardsScript, "AppleScript", args...)
	return err
}

// ClearPortForwards removes the forwards holding the given host ports from
// the interface at nicIndex.
func ClearPortForwards(ctx context.Context, id string, nicIndex int, hostPorts []int) error {
	if len(hostPorts) == 0 {
		return nil
	}
	args := []string{id}
	for _, port := range hostPorts {
		args = append(args, "--index", strconv.Itoa(nicIndex), strconv.Itoa(port))
	}
	_, err := runOSA(ctx, clearPortForwardsScript, "AppleScript", args...)
	return err
}

// AddQemuArgs appends raw QEMU arguments to the machine's configuration —
// the passthrough network adapters beyond the base pair, folder shares, and
// one-off directives ride.
func AddQemuArgs(ctx context.Context, id string, qemuArgs []string) error {
	if len(qemuArgs) == 0 {
		return nil
	}
	_, err := runOSA(ctx, addQemuArgsScript, "AppleScript", append([]string{id}, qemuArgs...)...)
	return err
}

// RemoveQemuArgs drops the QEMU arguments whose text exactly matches one of
// qemuArgs (the list is rebuilt without them).
func RemoveQemuArgs(ctx context.Context, id string, qemuArgs []string) error {
	if len(qemuArgs) == 0 {
		return nil
	}
	_, err := runOSA(ctx, removeQemuArgsScript, "AppleScript", append([]string{id}, qemuArgs...)...)
	return err
}

// ReadQemuArgs returns the machine's extra QEMU arguments verbatim, one per
// output line of the read script, in argument order.
func ReadQemuArgs(ctx context.Context, id string) ([]string, error) {
	out, err := runOSA(ctx, readQemuArgsScript, "AppleScript", id)
	if err != nil {
		return nil, err
	}
	args := []string{}
	for _, line := range strings.Split(out, "\n") {
		if arg := strings.TrimSpace(line); arg != "" {
			args = append(args, arg)
		}
	}
	return args, nil
}

var netdevIDPattern = regexp.MustCompile(`\bid=(net\d+)`)

// ReadQemuNetdevIDs returns the netN ids present in the machine's -netdev
// QEMU arguments, in argument order.
func ReadQemuNetdevIDs(ctx context.Context, id string) ([]string, error) {
	args, err := ReadQemuArgs(ctx, id)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-netdev") {
			continue
		}
		if match := netdevIDPattern.FindStringSubmatch(arg); len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			ids = append(ids, match[1])
		}
	}
	return ids, nil
}

// SetMACAddress sets the address of the interface at nicIndex (pair with
// RandomMAC — UTM cannot generate one itself).
func SetMACAddress(ctx context.Context, id string, nicIndex int, mac string) error {
	_, err := runOSA(ctx, setMACAddressScript, "AppleScript", id, strconv.Itoa(nicIndex), mac)
	return err
}

// AddRegistryPaths grants UTM sandbox access to the given paths by appending
// them to the machine's registry — required before a shared folder opens.
func AddRegistryPaths(ctx context.Context, id string, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	_, err := runOSA(ctx, addRegistryPathsScript, "AppleScript", append([]string{id}, paths...)...)
	return err
}
