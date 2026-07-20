package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

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

// networkAddressList is the bare GET /network/addresses document
// {addresses, total, source} — always the live view on this agent.
type networkAddressList struct {
	Addresses []networkAddress `json:"addresses"`
	// Entries returned (after filters and limit)
	Total int `json:"total"`
	// "live" — this agent has no collector database
	Source string `json:"source"`
}

// handleListNetworkAddresses mirrors GET /network/addresses (zoneweaver's
// shipped wire, sync 2026-07-17) over Go's stdlib interface enumeration —
// always LIVE (?live is ignored: this agent has no collector database).
// Honest vocabulary limits of a Go host, documented on the spec too:
//
//   - addrobj: Go has no ipadm addrobj vocabulary — the synthetic
//     "<ifname>/v4"|"<ifname>/v6" name is stable and round-trips.
//
//   - type: the stdlib cannot see DHCP-vs-static; IPv6 link-locals
//     (fe80::/10) answer "addrconf", everything else answers "static".
//
//     @Summary		List the host's IP addresses
//     @Description	Minimum role: viewer (the ip-addresses capability token). Zoneweaver's shipped listing wire (the converged wire, sync 2026-07-17), a BARE document — {addresses, total, source}; errors are {error, details?}. ALWAYS LIVE over Go's stdlib interface enumeration: this agent has no collector database, so ?live is accepted and IGNORED — every answer is the live view, source "live" top-level and per entry. Honest vocabulary limits of a Go host: addrobj is SYNTHETIC — Go has no ipadm address-object vocabulary, so entries are named <interface>/v4 or <interface>/v6 (stable, round-trips into the DELETE wildcard); type is INFERRED — the stdlib cannot see DHCP-vs-static, so IPv6 link-locals (fe80::/10) answer addrconf and everything else answers static (dhcp never appears); state is the interface's up/down flag (ok | down). total counts the entries returned (after filters and limit).
//     @Tags			Host Configuration
//     @Produce		json
//     @Param			interface	query	string	false	"Substring match on the interface name (zoneweaver's partial-match semantics, not exact)"
//     @Param			ip_version	query	string	false	"Filter by IP version (v4 | v6)"
//     @Param			type		query	string	false	"Filter by inferred type — this agent produces static and addrconf only (no DHCP visibility)"
//     @Param			state		query	string	false	"Filter by interface state — ok | down on this agent"
//     @Param			limit		query	int		false	"Cap on returned entries — defaults to 100 (zoneweaver's exact semantics); a positive integer overrides, anything else keeps the default"	default(100)
//     @Param			live		query	bool	false	"Accepted for wire parity and IGNORED — this agent is always live (no collector database)"
//     @Success		200	{object}	networkAddressList	"IP addresses (bare document, always live)"
//     @Failure		500	"Failed to get IP addresses"
//     @Router			/network/addresses [get]
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

	writeJSON(w, networkAddressList{
		Addresses: addresses,
		Total:     len(addresses),
		Source:    "live",
	})
}
