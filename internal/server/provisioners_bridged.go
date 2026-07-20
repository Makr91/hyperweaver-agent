package server

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// bridgedInterfaceRow is one row of GET /provisioning/bridged-interfaces.
type bridgedInterfaceRow struct {
	Name  string `json:"name"`
	Class string `json:"class"`
	// Status is omitted when VirtualBox reports none.
	Status   string `json:"status,omitempty"`
	Wireless bool   `json:"wireless"`
}

// bridgedInterfacesResponse is GET /provisioning/bridged-interfaces's answer.
type bridgedInterfacesResponse struct {
	Interfaces []bridgedInterfaceRow `json:"interfaces"`
	Default    string                `json:"default"`
	Total      int                   `json:"total"`
}

// handleBridgedInterfaces lists the host's bridgeable interfaces (VBoxManage
// list bridgedifs) — the UI's uplink dropdown and the source for
// provisioning.default_network_interface values. FLAT ROWS (converged with
// zoneweaver, sync 2026-07-17): every row is {name, class} — on this
// hypervisor every bridgeable interface is a physical adapter, so class is
// always "phys" (zoneweaver's vocabulary adds aggr/etherstub/simnet/overlay
// for its link families) — plus the ADDITIVE picker fields status ("up"|
// "down") and wireless (the sync proposal 2026-07-19: macOS lists pseudo and
// down interfaces the picker should filter). On darwin the hostonlynet
// families' vmnet backing bridges are excluded (BridgeCandidates). The
// `default` extra rides as before.
//
//	@Summary		Host bridgeable interfaces
//	@Description	Minimum role: viewer. VBoxManage list bridgedifs — the UI's uplink dropdown and the bridge/default-NIC picker's choices. FLAT ROWS (the converged wire, sync 2026-07-17 — one shape on both agents): every entry is {name, class}, class from each agent's own link vocabulary. On this hypervisor every bridgeable interface is a physical adapter, so class is always "phys"; zoneweaver's rows additionally speak aggr/etherstub/simnet/overlay for its link families. ADDITIVE picker fields (the sync proposal 2026-07-19): status ("up"|"down") and wireless — macOS lists pseudo and down interfaces the picker should filter. macOS additionally EXCLUDES the hostonlynet families' vmnet backing bridges (bridge100-style entries carrying a hostonlynet's own subnet — never real bridge candidates; vagrant #13025's picker hole). default echoes provisioning.default_network_interface.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	bridgedInterfacesResponse	"Interface rows"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/provisioning/bridged-interfaces [get]
func (s *Server) handleBridgedInterfaces(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	interfaces, err := machines.BridgeCandidates(r.Context(), exe)
	if err != nil {
		slog.Error("list bridged interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list bridged interfaces")
		return
	}
	rows := make([]bridgedInterfaceRow, 0, len(interfaces))
	for i := range interfaces {
		row := bridgedInterfaceRow{
			Name:     interfaces[i].Name,
			Class:    "phys",
			Wireless: interfaces[i].Wireless,
		}
		if interfaces[i].Status != "" {
			row.Status = strings.ToLower(interfaces[i].Status)
		}
		rows = append(rows, row)
	}
	writeJSON(w, bridgedInterfacesResponse{
		Interfaces: rows,
		Default:    s.cfg.Provisioning.DefaultNetworkInterface,
		Total:      len(rows),
	})
}
