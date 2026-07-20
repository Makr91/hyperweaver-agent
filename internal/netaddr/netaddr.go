// Package netaddr implements the /network/addresses mutation executors
// (zoneweaver's create/delete/enable/disable_ip_address ops).
package netaddr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The zoneweaver op names, verbatim (machine_name "system").
const (
	OpCreate  = "create_ip_address"
	OpDelete  = "delete_ip_address"
	OpEnable  = "enable_ip_address"
	OpDisable = "disable_ip_address"
)

// Metadata is the address task document (zoneweaver's wire fields verbatim).
type Metadata struct {
	Interface string `json:"interface,omitempty"`
	Type      string `json:"type,omitempty"`
	AddrObj   string `json:"addrobj"`
	Address   string `json:"address,omitempty"`
	Primary   bool   `json:"primary,omitempty"`
	Wait      int    `json:"wait,omitempty"`
	Temporary bool   `json:"temporary,omitempty"`
	Down      bool   `json:"down,omitempty"`
	Release   bool   `json:"release,omitempty"`
}

// MetadataJSON serializes task metadata for the queue.
func MetadataJSON(m *Metadata) (*string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// SplitAddrObj parses the synthetic "<interface>/v4|v6" addrobj.
func SplitAddrObj(addrobj string) (iface, version string, ok bool) {
	idx := strings.LastIndex(addrobj, "/")
	if idx <= 0 {
		return "", "", false
	}
	iface, version = addrobj[:idx], addrobj[idx+1:]
	if version != "v4" && version != "v6" {
		return "", "", false
	}
	return iface, version, true
}

// InterfaceAddresses lists an interface's live addresses of one version.
func InterfaceAddresses(iface, version string) ([]string, error) {
	nic, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	addrs, err := nic.Addrs()
	if err != nil {
		return nil, err
	}
	matches := []string{}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}
		isV4 := ipNet.IP.To4() != nil
		if (version == "v4") == isV4 {
			matches = append(matches, ipNet.String())
		}
	}
	return matches, nil
}

// RegisterExecutors wires the four address operations into the task queue.
func RegisterExecutors(queue *tasks.Queue) {
	queue.Register(OpCreate, tasks.Executor{Run: createAddress})
	queue.Register(OpDelete, tasks.Executor{Run: deleteAddress})
	queue.Register(OpEnable, tasks.Executor{Run: interfaceToggle(true)})
	queue.Register(OpDisable, tasks.Executor{Run: interfaceToggle(false)})
}

func parseMeta(task *tasks.Task) (*Metadata, error) {
	if len(task.Metadata) == 0 {
		return nil, errors.New("address task has no metadata")
	}
	meta := &Metadata{}
	if err := json.Unmarshal(task.Metadata, meta); err != nil {
		return nil, fmt.Errorf("parse address metadata: %w", err)
	}
	return meta, nil
}

func createAddress(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := parseMeta(task)
	if err != nil {
		return err
	}
	for name, set := range map[string]bool{
		"primary": meta.Primary, "temporary": meta.Temporary, "down": meta.Down,
	} {
		if set {
			out.Write("stderr", name+" has no analog on this platform (ipadm vocabulary) — skipped\n")
		}
	}
	switch meta.Type {
	case "dhcp":
		if runtime.GOOS != "windows" {
			return errors.New("dhcp address creation is Windows-only on this agent (no cross-distro verb)")
		}
		if derr := runTool(ctx, out, "netsh", "interface", "ipv4", "set", "address",
			"name="+meta.Interface, "source=dhcp"); derr != nil {
			return derr
		}
		out.Write("stdout", "Interface "+meta.Interface+" switched to DHCP\n")
		return nil
	case "static":
	default:
		return fmt.Errorf("type %s is not creatable on this agent (static everywhere, dhcp on Windows; addrconf/SLAAC is automatic)", meta.Type)
	}

	ip, ipNet, perr := net.ParseCIDR(meta.Address)
	if perr != nil {
		return fmt.Errorf("address must be CIDR (ip/prefix): %w", perr)
	}
	prefix, _ := ipNet.Mask.Size()
	v4 := ip.To4() != nil
	switch runtime.GOOS {
	case "windows":
		if v4 {
			mask := net.IP(net.CIDRMask(prefix, 32)).String()
			err = runTool(ctx, out, "netsh", "interface", "ipv4", "add", "address",
				"name="+meta.Interface, "addr="+ip.String(), "mask="+mask)
		} else {
			err = runTool(ctx, out, "netsh", "interface", "ipv6", "add", "address",
				"interface="+meta.Interface, "address="+ip.String()+"/"+strconv.Itoa(prefix))
		}
	case "darwin":
		out.Write("stdout", "macOS note: the address applies live (ifconfig) and does not persist across reboot\n")
		if v4 {
			mask := net.IP(net.CIDRMask(prefix, 32)).String()
			err = runTool(ctx, out, "ifconfig", meta.Interface, "alias", ip.String(), "netmask", mask)
		} else {
			err = runTool(ctx, out, "ifconfig", meta.Interface, "inet6", ip.String(),
				"prefixlen", strconv.Itoa(prefix), "alias")
		}
	default:
		err = runTool(ctx, out, "ip", "addr", "add", meta.Address, "dev", meta.Interface)
	}
	if err != nil {
		return err
	}
	out.Write("stdout", "Address "+meta.Address+" added to "+meta.Interface+"\n")
	return nil
}

// resolveDelete pins the exact live CIDR the delete targets.
func resolveDelete(meta *Metadata) (iface, cidr string, v4 bool, err error) {
	iface, version, ok := SplitAddrObj(meta.AddrObj)
	if !ok {
		return "", "", false, fmt.Errorf("addrobj %q is not <interface>/v4|v6 (the listing's names)", meta.AddrObj)
	}
	live, lerr := InterfaceAddresses(iface, version)
	if lerr != nil {
		return "", "", false, lerr
	}
	v4 = version == "v4"
	if meta.Address != "" {
		want, _, perr := net.ParseCIDR(meta.Address)
		if perr != nil {
			want = net.ParseIP(meta.Address)
		}
		if want == nil {
			return "", "", false, fmt.Errorf("address %q is not an IP or CIDR", meta.Address)
		}
		for _, candidate := range live {
			ip, _, _ := net.ParseCIDR(candidate)
			if ip != nil && ip.Equal(want) {
				return iface, candidate, v4, nil
			}
		}
		return "", "", false, fmt.Errorf("interface %s does not carry %s (live: %s)",
			iface, meta.Address, strings.Join(live, ", "))
	}
	switch len(live) {
	case 0:
		return "", "", false, fmt.Errorf("interface %s carries no %s address", iface, version)
	case 1:
		return iface, live[0], v4, nil
	}
	return "", "", false, fmt.Errorf("interface %s carries several %s addresses (%s) — disambiguate with ?address=",
		iface, version, strings.Join(live, ", "))
}

func deleteAddress(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := parseMeta(task)
	if err != nil {
		return err
	}
	iface, cidr, v4, err := resolveDelete(meta)
	if err != nil {
		return err
	}
	ip, ipNet, _ := net.ParseCIDR(cidr)
	prefix, _ := ipNet.Mask.Size()

	if meta.Release {
		if runtime.GOOS == "windows" {
			if rerr := runTool(ctx, out, "ipconfig", "/release", iface); rerr != nil {
				out.Write("stderr", "DHCP release failed (continuing with the delete): "+rerr.Error()+"\n")
			}
		} else {
			out.Write("stderr", "release has no analog on this platform — skipped\n")
		}
	}

	switch runtime.GOOS {
	case "windows":
		if v4 {
			err = runTool(ctx, out, "netsh", "interface", "ipv4", "delete", "address",
				"name="+iface, "addr="+ip.String())
		} else {
			err = runTool(ctx, out, "netsh", "interface", "ipv6", "delete", "address",
				"interface="+iface, "address="+ip.String())
		}
	case "darwin":
		if v4 {
			err = runTool(ctx, out, "ifconfig", iface, "-alias", ip.String())
		} else {
			err = runTool(ctx, out, "ifconfig", iface, "inet6", ip.String(), "-alias")
		}
	default:
		err = runTool(ctx, out, "ip", "addr", "del", ip.String()+"/"+strconv.Itoa(prefix), "dev", iface)
	}
	if err != nil {
		return err
	}
	out.Write("stdout", "Address "+cidr+" removed from "+iface+"\n")
	return nil
}

// interfaceToggle builds the enable/disable executor (interface-level — no
// per-address enable exists off illumos).
func interfaceToggle(up bool) func(context.Context, *tasks.Task, *tasks.OutputWriter) error {
	return func(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
		meta, err := parseMeta(task)
		if err != nil {
			return err
		}
		iface, _, ok := SplitAddrObj(meta.AddrObj)
		if !ok {
			return fmt.Errorf("addrobj %q is not <interface>/v4|v6 (the listing's names)", meta.AddrObj)
		}
		word := map[bool]string{true: "enabled", false: "disabled"}[up]
		out.Write("stdout", "Interface-level toggle: this platform has no per-address enable — "+
			iface+" itself is being "+word+"\n")
		switch runtime.GOOS {
		case "windows":
			err = runTool(ctx, out, "netsh", "interface", "set", "interface",
				"name="+iface, "admin="+word)
		case "darwin":
			state := map[bool]string{true: "up", false: "down"}[up]
			err = runTool(ctx, out, "ifconfig", iface, state)
		default:
			state := map[bool]string{true: "up", false: "down"}[up]
			err = runTool(ctx, out, "ip", "link", "set", "dev", iface, state)
		}
		if err != nil {
			return err
		}
		out.Write("stdout", "Interface "+iface+" "+word+"\n")
		return nil
	}
}

// runTool executes one platform command, streaming output into the task.
func runTool(ctx context.Context, out *tasks.OutputWriter, name string, args ...string) error {
	out.Write("stdout", "Executing: "+name+" "+strings.Join(args, " ")+"\n")
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	combined, cerr := cmd.CombinedOutput()
	if len(combined) > 0 {
		out.Write("stdout", string(combined))
	}
	if cerr != nil {
		out.Write("stderr", "Address command failed: "+cerr.Error()+"\n")
		return fmt.Errorf("%s: %w", name, cerr)
	}
	return nil
}
