package server

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/hostname"
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

// handleNetworkAddressStub answers every /network/addresses mutation with an
// honest 501 (Mark's scope ruling, sync 2026-07-17: the listing is real,
// mutations wait for a future session). One handler covers POST, the DELETE
// {addrobj...} wildcard, and the PUT {rest...} wildcard — Go 1.22 ServeMux
// forbids segments after a "..." wildcard, so the enable/disable verbs
// cannot be their own patterns; the suffix would be split here if the stub
// ever grew real behavior, and today every shape refuses identically.
func (s *Server) handleNetworkAddressStub(w http.ResponseWriter, _ *http.Request) {
	netconfigError(w, http.StatusNotImplemented,
		"IP address management is not implemented on this agent yet — the listing is read-only (a future session expands it)", "")
}
