package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/hostname"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Host network configuration (/network/hostname, /network/addresses — the
// converged wire, sync 2026-07-17): zoneweaver's shipped
// NetworkQueryController/NetworkModificationController family, mirrored on
// this agent. The controller family answers BARE documents — no
// success/message/timestamp envelope; errors are {error} or {error, details}
// (taskError's shape, with an optional details field).

// netconfigError writes this controller family's error shape:
// {error, details?} — zoneweaver's exact wire.
func netconfigError(w http.ResponseWriter, status int, errText, details string) {
	payload := map[string]string{"error": errText}
	if details != "" {
		payload["details"] = details
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write netconfig error response", "error", err)
	}
}

// persistedHostname reads the platform's PERSISTED/configured host name —
// zoneweaver's /etc/nodename read, per-OS here. ok=false means no persisted
// source exists or it is unreadable (the wire answers nodename_file: null).
//   - Linux: /etc/hostname content, trimmed.
//   - Windows: the PENDING computer name from the registry via `reg query`
//     (a Rename-Computer awaiting reboot shows here before os.Hostname does;
//     exec keeps this file cross-platform — no build-tagged registry import).
//   - macOS: `scutil --get HostName` (unset → no persisted name).
func persistedHostname(r *http.Request) (string, bool) {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.CommandContext(r.Context(), "reg", "query",
			`HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`,
			"/v", "ComputerName")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 3 && fields[0] == "ComputerName" && fields[1] == "REG_SZ" {
				return strings.Join(fields[2:], " "), true
			}
		}
		return "", false
	case "darwin":
		cmd := exec.CommandContext(r.Context(), "scutil", "--get", "HostName")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return "", false
		}
		name := strings.TrimSpace(string(out))
		return name, name != ""
	default:
		raw, err := os.ReadFile("/etc/hostname")
		if err != nil {
			return "", false
		}
		name := strings.TrimSpace(string(raw))
		return name, name != ""
	}
}

// handleGetHostname mirrors GET /network/hostname (zoneweaver's shipped
// wire, sync 2026-07-17): the BARE document {hostname, nodename_file,
// system_hostname, matches, warning}. hostname is the SYSTEM hostname
// (zoneweaver's semantics); nodename_file is null when no persisted name
// exists; warning is null when consistent.
func (s *Server) handleGetHostname(w http.ResponseWriter, r *http.Request) {
	system, err := os.Hostname()
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to get hostname", err.Error())
		return
	}

	persisted, ok := persistedHostname(r)
	matches := true
	if ok {
		matches = persisted == system
		if runtime.GOOS == "windows" {
			// Windows computer names are case-insensitive.
			matches = strings.EqualFold(persisted, system)
		}
	}

	var warning any
	if !matches {
		warning = "The persisted host name " + persisted + " does not match the live system hostname " + system
		if runtime.GOOS == "windows" {
			warning = "Computer rename to " + persisted + " is pending — the live hostname stays " + system + " until the next reboot"
		}
	}
	var nodenameFile any
	if ok {
		nodenameFile = persisted
	}
	writeJSON(w, map[string]any{
		"hostname":        system,
		"nodename_file":   nodenameFile,
		"system_hostname": system,
		"matches":         matches,
		"warning":         warning,
	})
}

// Zoneweaver's overall hostname shape gate (its exact regex): alphanumeric
// edges, hyphens and dots inside, 253 characters at most. The per-label
// checks below refine it with their own messages.
var hostnameShapePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-.]{0,251}[a-zA-Z0-9])?$`)

// validateHostnameRequest applies zoneweaver's exact staged validation and
// answers its exact message for the first failed stage ("" = valid).
func validateHostnameRequest(name string) string {
	if !hostnameShapePattern.MatchString(name) {
		return "Invalid hostname format. Must be alphanumeric with hyphens and dots, 1-253 characters"
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "Invalid hostname format. Each part between dots must be 1-63 characters"
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "Invalid hostname format. Each part must start and end with alphanumeric characters"
		}
	}
	return ""
}

// hostnameUpdateRequest is the PUT body. Hostname is a pointer so a missing
// key and a non-string both land on zoneweaver's "required" refusal.
type hostnameUpdateRequest struct {
	Hostname         *string `json:"hostname"`
	ApplyImmediately bool    `json:"apply_immediately"`
}

// handleSetHostname mirrors PUT /network/hostname (zoneweaver's shipped
// wire, sync 2026-07-17): queue the async set_hostname task (MachineName
// "system", HIGH priority — zoneweaver's choice) and answer 202 with the
// converged body. requires_reboot is PER-PLATFORM honest (the sync ruling:
// "surface requires_restart honestly where the OS demands it"): Windows
// renames land at reboot; Linux/macOS apply live.
func (s *Server) handleSetHostname(w http.ResponseWriter, r *http.Request) {
	var body hostnameUpdateRequest
	if err := decodeBody(r, &body); err != nil || body.Hostname == nil {
		netconfigError(w, http.StatusBadRequest, "hostname is required and must be a string", "")
		return
	}
	name := *body.Hostname
	if problem := validateHostnameRequest(name); problem != "" {
		netconfigError(w, http.StatusBadRequest, problem, "")
		return
	}

	metadata, err := hostname.MetadataJSON(hostname.Metadata{
		Hostname:         name,
		ApplyImmediately: body.ApplyImmediately,
	})
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to create hostname change task", err.Error())
		return
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   hostname.Op,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue set_hostname", "hostname", name, "error", err)
		netconfigError(w, http.StatusInternalServerError, "Failed to create hostname change task", err.Error())
		return
	}
	slog.Info("hostname change queued", "hostname", name,
		"apply_immediately", body.ApplyImmediately, "by", auth.FromContext(r.Context()).Name)

	requiresReboot := runtime.GOOS == "windows"
	rebootReason := ""
	note := "apply_immediately applies the new hostname live on " + runtime.GOOS
	if requiresReboot {
		rebootReason = "Windows applies a computer rename at the next reboot"
		note = "apply_immediately cannot take effect on Windows — the rename lands at the next reboot"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(map[string]any{
		"success":           true,
		"message":           "Hostname change task created for: " + name,
		"task_id":           task.ID,
		"hostname":          name,
		"apply_immediately": body.ApplyImmediately,
		"requires_reboot":   requiresReboot,
		"reboot_reason":     rebootReason,
		"note":              note,
	}); werr != nil {
		slog.Error("write hostname response", "error", werr)
	}
}

// networkAddress is one GET /network/addresses entry — zoneweaver's shipped
// shape {addrobj, interface, type, state, addr, ip_version, source}.
type networkAddress struct {
	AddrObj   string `json:"addrobj"`
	Interface string `json:"interface"`
	Type      string `json:"type"`
	State     string `json:"state"`
	Addr      string `json:"addr"`
	IPVersion string `json:"ip_version"`
	Source    string `json:"source"`
}

// handleListNetworkAddresses mirrors GET /network/addresses (zoneweaver's
// shipped wire, sync 2026-07-17) over Go's stdlib interface enumeration —
// always LIVE (?live is ignored: this agent has no collector database).
// Honest vocabulary limits of a Go host, documented on the spec too:
//   - addrobj: Go has no ipadm addrobj vocabulary — the synthetic
//     "<ifname>/v4"|"<ifname>/v6" name is stable and round-trips.
//   - type: the stdlib cannot see DHCP-vs-static; IPv6 link-locals
//     (fe80::/10) answer "addrconf", everything else answers "static".
func (s *Server) handleListNetworkAddresses(w http.ResponseWriter, r *http.Request) {
	interfaces, err := net.Interfaces()
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to get IP addresses", err.Error())
		return
	}

	query := r.URL.Query()
	filterInterface := query.Get("interface")
	filterVersion := query.Get("ip_version")
	filterType := query.Get("type")
	filterState := query.Get("state")
	// zoneweaver defaults the cap to 100 (its ?limit=100 default) — matched
	// exactly; a positive ?limit overrides, junk keeps the default.
	limit := 100
	if raw := query.Get("limit"); raw != "" {
		if parsed, perr := strconv.Atoi(raw); perr == nil && parsed > 0 {
			limit = parsed
		}
	}

	addresses := []networkAddress{}
	for _, iface := range interfaces {
		// Partial interface match — zoneweaver's semantics (substring, not
		// exact).
		if filterInterface != "" && !strings.Contains(iface.Name, filterInterface) {
			continue
		}
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "ok"
		}
		if filterState != "" && state != filterState {
			continue
		}
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, isIPNet := addr.(*net.IPNet)
			if !isIPNet || ipNet.IP == nil {
				continue
			}
			version := "v6"
			if ipNet.IP.To4() != nil {
				version = "v4"
			}
			if filterVersion != "" && version != filterVersion {
				continue
			}
			addrType := "static"
			if version == "v6" && ipNet.IP.IsLinkLocalUnicast() {
				addrType = "addrconf"
			}
			if filterType != "" && addrType != filterType {
				continue
			}
			addresses = append(addresses, networkAddress{
				AddrObj:   iface.Name + "/" + version,
				Interface: iface.Name,
				Type:      addrType,
				State:     state,
				Addr:      addr.String(),
				IPVersion: version,
				Source:    "live",
			})
		}
	}
	if limit > 0 && len(addresses) > limit {
		addresses = addresses[:limit]
	}

	writeJSON(w, map[string]any{
		"addresses": addresses,
		"total":     len(addresses),
		"source":    "live",
	})
}

// The IP-suggestions feed (the converged cross-agent wire, sync 2026-07-18 —
// Mark's static-IP picker ask, zoneweaver's proposed shape adopted verbatim):
// the default-route interface anchors the host's own network; the ARP/NDP
// neighbor table plus the addresses machine documents already pin form the
// used set; the first free host addresses become suggestions. ADVISORY only —
// a suggestion is a point-in-time observation, never a reservation.

const (
	ipSuggestionsDefault = 10      // suggestions when ?count is absent
	ipSuggestionsMax     = 256     // ?count ceiling
	ipSuggestionsScanCap = 1 << 16 // candidates scanned before giving up (giant subnets)
)

// parenIPPattern extracts the "(192.168.1.1)" IPv4 of BSD-style arp -an rows.
var parenIPPattern = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)`)

// ipv4ToUint / uintToIPv4 are the suggestion scan's address arithmetic.
func ipv4ToUint(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func uintToIPv4(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// interfaceByAddr finds the interface holding the given IPv4 — how the
// Windows route table's interface COLUMN (an address, not a name) resolves.
func interfaceByAddr(local net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range interfaces {
		addrs, aerr := interfaces[i].Addrs()
		if aerr != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(local) {
				return &interfaces[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface holds the default route's address %s", local)
}

// defaultRoute reads the host's IPv4 default route — gateway + interface —
// from the platform's own routing tool (Go's stdlib has no route-table view):
// `route print -4` on Windows (the interface column is an ADDRESS), `route -n
// get default` on macOS, `ip route show default` elsewhere.
func defaultRoute(r *http.Request) (net.IP, *net.Interface, error) {
	noDefault := errors.New("no default route found on this host")
	switch runtime.GOOS {
	case "windows":
		cmd := exec.CommandContext(r.Context(), "route", "print", "-4")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return nil, nil, fmt.Errorf("route print: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
				continue
			}
			gateway := net.ParseIP(fields[2])
			local := net.ParseIP(fields[3])
			if gateway == nil || gateway.To4() == nil || local == nil {
				continue
			}
			iface, ferr := interfaceByAddr(local)
			if ferr != nil {
				return nil, nil, ferr
			}
			return gateway.To4(), iface, nil
		}
		return nil, nil, noDefault
	case "darwin":
		cmd := exec.CommandContext(r.Context(), "route", "-n", "get", "default")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return nil, nil, fmt.Errorf("route get default: %w", err)
		}
		var gateway net.IP
		var ifaceName string
		for _, line := range strings.Split(string(out), "\n") {
			key, value, found := strings.Cut(strings.TrimSpace(line), ":")
			if !found {
				continue
			}
			switch key {
			case "gateway":
				gateway = net.ParseIP(strings.TrimSpace(value))
			case "interface":
				ifaceName = strings.TrimSpace(value)
			}
		}
		if gateway == nil || gateway.To4() == nil || ifaceName == "" {
			return nil, nil, noDefault
		}
		iface, ferr := net.InterfaceByName(ifaceName)
		if ferr != nil {
			return nil, nil, ferr
		}
		return gateway.To4(), iface, nil
	default:
		cmd := exec.CommandContext(r.Context(), "ip", "route", "show", "default")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			return nil, nil, fmt.Errorf("ip route show default: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			var gateway net.IP
			var ifaceName string
			for i := 0; i+1 < len(fields); i++ {
				switch fields[i] {
				case "via":
					gateway = net.ParseIP(fields[i+1])
				case "dev":
					ifaceName = fields[i+1]
				}
			}
			if gateway == nil || gateway.To4() == nil || ifaceName == "" {
				continue
			}
			iface, ferr := net.InterfaceByName(ifaceName)
			if ferr != nil {
				return nil, nil, ferr
			}
			return gateway.To4(), iface, nil
		}
		return nil, nil, noDefault
	}
}

// interfaceSubnet picks the interface's IPv4 subnet — the one containing the
// gateway when several ride the interface — plus the host's own IPv4s there
// (they join the used set).
func interfaceSubnet(iface *net.Interface, gateway net.IP) (*net.IPNet, []net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	var subnet *net.IPNet
	var own []net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipNet.IP.To4()
		if v4 == nil {
			continue
		}
		own = append(own, v4)
		ones, _ := ipNet.Mask.Size()
		mask := net.CIDRMask(ones, 32)
		candidate := &net.IPNet{IP: v4.Mask(mask), Mask: mask}
		if subnet == nil || candidate.Contains(gateway) {
			subnet = candidate
		}
	}
	if subnet == nil {
		return nil, nil, fmt.Errorf("interface %s carries no IPv4 address", iface.Name)
	}
	return subnet, own, nil
}

// neighborIPs reads the host's ARP/NDP neighbor table — the live used-IP
// evidence. A failed read degrades to an empty list (narrated in the log):
// the suggestions then lean on the document-pinned addresses alone.
func neighborIPs(r *http.Request) []net.IP {
	parseFirstFields := func(out []byte, skipStates bool) []net.IP {
		var ips []net.IP
		for _, line := range strings.Split(string(out), "\n") {
			if skipStates && (strings.Contains(line, "FAILED") || strings.Contains(line, "INCOMPLETE")) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if ip := net.ParseIP(fields[0]); ip != nil && ip.To4() != nil {
				ips = append(ips, ip.To4())
			}
		}
		return ips
	}
	parseParens := func(out []byte) []net.IP {
		var ips []net.IP
		for _, match := range parenIPPattern.FindAllStringSubmatch(string(out), -1) {
			if ip := net.ParseIP(match[1]); ip != nil && ip.To4() != nil {
				ips = append(ips, ip.To4())
			}
		}
		return ips
	}
	arpDashAN := func() []net.IP {
		cmd := exec.CommandContext(r.Context(), "arp", "-an")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			slog.Warn("neighbor table read failed — suggestions lean on document addresses only", "error", err)
			return nil
		}
		return parseParens(out)
	}
	switch runtime.GOOS {
	case "windows":
		cmd := exec.CommandContext(r.Context(), "arp", "-a")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			slog.Warn("neighbor table read failed — suggestions lean on document addresses only", "error", err)
			return nil
		}
		return parseFirstFields(out, false)
	case "darwin":
		return arpDashAN()
	default:
		cmd := exec.CommandContext(r.Context(), "ip", "neigh", "show")
		cmd.SysProcAttr = procattr.NoConsole()
		out, err := cmd.Output()
		if err != nil {
			// net-tools fallback for hosts without iproute2.
			return arpDashAN()
		}
		return parseFirstFields(out, true)
	}
}

// documentAddresses collects every IPv4 the stored machine documents pin
// (networks[].address) — the agent's own assignments: a powered-off machine's
// static IP never shows in ARP, but it IS taken.
func (s *Server) documentAddresses(ctx context.Context) []net.IP {
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		slog.Warn("machine list failed — IP suggestions skip document addresses", "error", err)
		return nil
	}
	var ips []net.IP
	for _, machine := range list {
		config := machines.ParseConfiguration(machine)
		for _, entry := range config.List("networks") {
			network, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			address, _ := network["address"].(string)
			if address == "" {
				continue
			}
			// Documents may carry CIDR-suffixed addresses; the bare IP counts.
			bare, _, _ := strings.Cut(address, "/")
			if ip := net.ParseIP(bare); ip != nil && ip.To4() != nil {
				ips = append(ips, ip.To4())
			}
		}
	}
	return ips
}

// handleIPSuggestions serves GET /network/ip-suggestions (the converged
// cross-agent wire, sync 2026-07-18): {interface, subnet, gateway, used,
// suggestions, total_used}. interface = the default-route link, used =
// ARP/NDP neighbors + document-pinned machine addresses + the gateway and the
// host's own IPs, suggestions = the first ?count (default 10, max 256) unused
// host addresses in the subnet. ADVISORY only — never a reservation; the
// picker keeps a free-text escape. IPv4 only (an ARP-anchored feed).
func (s *Server) handleIPSuggestions(w http.ResponseWriter, r *http.Request) {
	gateway, iface, err := defaultRoute(r)
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to resolve the default route", err.Error())
		return
	}
	subnet, own, err := interfaceSubnet(iface, gateway)
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to resolve the default-route subnet", err.Error())
		return
	}

	count := ipSuggestionsDefault
	if raw := r.URL.Query().Get("count"); raw != "" {
		if parsed, perr := strconv.Atoi(raw); perr == nil && parsed > 0 {
			count = parsed
		}
	}
	if count > ipSuggestionsMax {
		count = ipSuggestionsMax
	}

	used := map[uint32]bool{}
	take := func(ips []net.IP) {
		for _, ip := range ips {
			if subnet.Contains(ip) {
				used[ipv4ToUint(ip)] = true
			}
		}
	}
	take(neighborIPs(r))
	take(s.documentAddresses(r.Context()))
	take(own)
	take([]net.IP{gateway})

	ones, _ := subnet.Mask.Size()
	network := ipv4ToUint(subnet.IP)
	broadcast := network | (^uint32(0) >> ones)
	suggestions := []string{}
	for candidate, scanned := network+1, 0; candidate < broadcast &&
		len(suggestions) < count && scanned < ipSuggestionsScanCap; candidate, scanned = candidate+1, scanned+1 {
		if !used[candidate] {
			suggestions = append(suggestions, uintToIPv4(candidate).String())
		}
	}

	usedInts := make([]uint32, 0, len(used))
	for value := range used {
		usedInts = append(usedInts, value)
	}
	sort.Slice(usedInts, func(i, j int) bool { return usedInts[i] < usedInts[j] })
	usedList := make([]string, 0, len(usedInts))
	for _, value := range usedInts {
		usedList = append(usedList, uintToIPv4(value).String())
	}

	writeJSON(w, map[string]any{
		"interface":   iface.Name,
		"subnet":      subnet.String(),
		"gateway":     gateway.String(),
		"used":        usedList,
		"suggestions": suggestions,
		"total_used":  len(usedList),
	})
}
