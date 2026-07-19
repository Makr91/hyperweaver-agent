package server

import (
	"log/slog"
	"net/http"
	"runtime"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/netaddr"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The /network/addresses mutation surface — zoneweaver's task wire;
// impossible-for-this-platform shapes refuse at the HTTP layer.

// queueAddressTask creates one address task and answers zoneweaver's 202.
func (s *Server) queueAddressTask(w http.ResponseWriter, r *http.Request,
	operation string, meta *netaddr.Metadata, message string, extra map[string]any,
) {
	metadata, err := netaddr.MetadataJSON(meta)
	if err != nil {
		netconfigError(w, http.StatusInternalServerError, "Failed to create "+operation+" task", err.Error())
		return
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   operation,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    metadata,
	})
	if err != nil {
		slog.Error("queue address task", "operation", operation, "error", err)
		netconfigError(w, http.StatusInternalServerError, "Failed to create "+operation+" task", err.Error())
		return
	}
	slog.Info("address task queued", "operation", operation, "addrobj", meta.AddrObj,
		"by", auth.FromContext(r.Context()).Name)
	payload := map[string]any{
		"success": true,
		"message": message,
		"task_id": task.ID,
		"addrobj": meta.AddrObj,
	}
	for k, v := range extra {
		payload[k] = v
	}
	writeJSONStatus(w, http.StatusAccepted, payload)
}

// handleCreateNetworkAddress serves POST /network/addresses.
func (s *Server) handleCreateNetworkAddress(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Interface string `json:"interface"`
		Type      string `json:"type"`
		AddrObj   string `json:"addrobj"`
		Address   string `json:"address"`
		Primary   bool   `json:"primary"`
		Wait      int    `json:"wait"`
		Temporary bool   `json:"temporary"`
		Down      bool   `json:"down"`
	}
	if err := decodeBody(r, &body); err != nil {
		netconfigError(w, http.StatusBadRequest, "Invalid JSON body", "")
		return
	}
	if body.Interface == "" || body.Type == "" || body.AddrObj == "" {
		netconfigError(w, http.StatusBadRequest, "interface, type, and addrobj are required", "")
		return
	}
	switch body.Type {
	case "static":
		if body.Address == "" {
			netconfigError(w, http.StatusBadRequest, "address is required for static type", "")
			return
		}
	case "dhcp":
		if runtime.GOOS != "windows" {
			netconfigError(w, http.StatusBadRequest,
				"dhcp address creation is Windows-only on this agent (no cross-distro verb on "+runtime.GOOS+")", "")
			return
		}
	case "addrconf":
		netconfigError(w, http.StatusBadRequest,
			"addrconf has no verb on this agent — IPv6 SLAAC configures itself", "")
		return
	default:
		netconfigError(w, http.StatusBadRequest, "type must be one of: static, dhcp, addrconf", "")
		return
	}
	s.queueAddressTask(w, r, netaddr.OpCreate, &netaddr.Metadata{
		Interface: body.Interface,
		Type:      body.Type,
		AddrObj:   body.AddrObj,
		Address:   body.Address,
		Primary:   body.Primary,
		Wait:      body.Wait,
		Temporary: body.Temporary,
		Down:      body.Down,
	}, "IP address creation task created for "+body.AddrObj, map[string]any{
		"type":      body.Type,
		"interface": body.Interface,
	})
}

// handleDeleteNetworkAddress serves DELETE /network/addresses/{addrobj...}.
func (s *Server) handleDeleteNetworkAddress(w http.ResponseWriter, r *http.Request) {
	addrobj := r.PathValue("addrobj")
	iface, version, ok := netaddr.SplitAddrObj(addrobj)
	if !ok {
		netconfigError(w, http.StatusBadRequest,
			"addrobj must be the listing's <interface>/v4|v6 form", "")
		return
	}
	live, err := netaddr.InterfaceAddresses(iface, version)
	if err != nil {
		netconfigError(w, http.StatusNotFound, "Address object "+addrobj+" not found", err.Error())
		return
	}
	address := r.URL.Query().Get("address")
	if address == "" && len(live) == 0 {
		netconfigError(w, http.StatusNotFound, "Address object "+addrobj+" not found",
			"interface "+iface+" carries no "+version+" address")
		return
	}
	if address == "" && len(live) > 1 {
		netconfigError(w, http.StatusBadRequest,
			"interface "+iface+" carries several "+version+" addresses — disambiguate with ?address=",
			strings.Join(live, ", "))
		return
	}
	release := r.URL.Query().Get("release") == "true"
	s.queueAddressTask(w, r, netaddr.OpDelete, &netaddr.Metadata{
		AddrObj: addrobj,
		Address: address,
		Release: release,
	}, "IP address deletion task created for "+addrobj, map[string]any{
		"release": release,
	})
}

// handleNetworkAddressAction serves PUT /network/addresses/{rest...} — the
// enable/disable verbs split from the one wildcard here.
func (s *Server) handleNetworkAddressAction(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	addrobj, action := "", ""
	for _, candidate := range []string{"/enable", "/disable"} {
		if trimmed, found := strings.CutSuffix(rest, candidate); found {
			addrobj, action = trimmed, strings.TrimPrefix(candidate, "/")
			break
		}
	}
	if action == "" {
		netconfigError(w, http.StatusNotFound,
			"Unknown address action — PUT /network/addresses/{addrobj}/enable or /disable", "")
		return
	}
	iface, _, ok := netaddr.SplitAddrObj(addrobj)
	if !ok {
		netconfigError(w, http.StatusBadRequest,
			"addrobj must be the listing's <interface>/v4|v6 form", "")
		return
	}
	operation := netaddr.OpEnable
	if action == "disable" {
		operation = netaddr.OpDisable
	}
	s.queueAddressTask(w, r, operation, &netaddr.Metadata{AddrObj: addrobj},
		"IP address "+action+" task created for "+addrobj, map[string]any{
			"note": "no per-address enable exists on " + runtime.GOOS + " — the toggle applies to interface " + iface + " itself",
		})
}
