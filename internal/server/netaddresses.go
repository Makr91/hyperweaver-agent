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

// addressTaskResponse is the bare 202 task-queued document every
// /network/addresses mutation answers (creation adds type+interface,
// deletion adds release, enable/disable add note).
type addressTaskResponse struct {
	// Always true on a queued mutation.
	Success bool `json:"success"`
	// Human-readable confirmation naming the addrobj.
	Message string `json:"message"`
	// The queued task's id — poll it via GET /tasks/{taskId}.
	TaskID string `json:"task_id"`
	// The address object the task targets (the synthetic <interface>/v4|v6).
	AddrObj string `json:"addrobj"`
	// Creation only: the requested address type.
	Type string `json:"type,omitempty"`
	// Creation only: the interface the address was created on.
	Interface string `json:"interface,omitempty"`
	// Deletion only: whether a DHCP-lease release was requested.
	Release *bool `json:"release,omitempty"`
	// Enable/disable only: the interface-level honesty note.
	Note string `json:"note,omitempty"`
}

// createNetworkAddressRequest is POST /network/addresses' JSON body.
type createNetworkAddressRequest struct {
	// The host interface the address lives on.
	Interface string `json:"interface"`
	// One of static (everywhere), dhcp (Windows only), addrconf (always refused).
	Type string `json:"type"`
	// The synthetic <interface>/v4|v6 name (the listing's vocabulary).
	AddrObj string `json:"addrobj"`
	// CIDR, required for static.
	Address string `json:"address"`
	// ipadm vocabulary with no analog here — accepted for wire parity, narrated as skipped.
	Primary bool `json:"primary"`
	// ipadm vocabulary with no analog here — accepted for wire parity, narrated as skipped.
	Wait int `json:"wait"`
	// ipadm vocabulary with no analog here — accepted for wire parity, narrated as skipped.
	Temporary bool `json:"temporary"`
	// ipadm vocabulary with no analog here — accepted for wire parity, narrated as skipped.
	Down bool `json:"down"`
}

// queueAddressTask creates one address task and answers zoneweaver's 202.
func (s *Server) queueAddressTask(w http.ResponseWriter, r *http.Request,
	operation string, meta *netaddr.Metadata, resp *addressTaskResponse,
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
	resp.Success = true
	resp.TaskID = task.ID
	resp.AddrObj = meta.AddrObj
	writeJSONStatus(w, http.StatusAccepted, resp)
}

// handleCreateNetworkAddress serves POST /network/addresses.
//
//	@Summary		Create an IP address (task)
//	@Description	Minimum role: operator. Queues create_ip_address (zoneweaver's op, machine_name "system" — Mark's build order 2026-07-19 replaced the 501 stub). PER-OS HONESTY, refused at the POST so no doomed task queues: type static works everywhere (Windows netsh, Linux `ip addr add`, macOS ifconfig alias — the macOS apply is LIVE and does not persist across reboot, narrated in the task output); type dhcp is Windows-only (netsh source=dhcp — Linux/macOS have no cross-distro verb → 400); type addrconf always 400 (IPv6 SLAAC configures itself). address must be CIDR for static. primary/wait/temporary/down are ipadm vocabulary with no analog here — accepted for wire parity, narrated as skipped.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			request	body	createNetworkAddressRequest	true	"Address creation request"
//	@Success		202	{object}	addressTaskResponse	"Creation task queued ({success, message, task_id, addrobj, type, interface})"
//	@Failure		400	"Missing interface/type/addrobj, missing address for static, non-CIDR address, dhcp off-Windows, or addrconf"
//	@Router			/network/addresses [post]
func (s *Server) handleCreateNetworkAddress(w http.ResponseWriter, r *http.Request) {
	var body createNetworkAddressRequest
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
	}, &addressTaskResponse{
		Message:   "IP address creation task created for " + body.AddrObj,
		Type:      body.Type,
		Interface: body.Interface,
	})
}

// handleDeleteNetworkAddress serves DELETE /network/addresses/{addrobj...}.
//
//	@Summary		Delete an IP address (task)
//	@Description	Minimum role: operator. Queues delete_ip_address (netsh / `ip addr del` / ifconfig -alias). The synthetic <interface>/<version> addrobj can cover SEVERAL live addresses — ?address= disambiguates (this agent's extension; without it, exactly one live address of that version must exist or the request answers 400 listing the candidates). ?release=true releases the DHCP lease first on Windows (ipconfig /release; narrated skip elsewhere). A missing interface or an addrobj with no live address answers 404.
//	@Tags			Host Configuration
//	@Produce		json
//	@Param			addrobj	path	string	true	"The listing's addrobj value — may carry a slash (<interface>/v4)"
//	@Param			address	query	string	false	"Which of the addrobj's live addresses to delete (IP or CIDR) — required when several exist"
//	@Param			release	query	bool	false	"Release the DHCP lease first (Windows; narrated skip elsewhere)"
//	@Success		202	{object}	addressTaskResponse	"Deletion task queued ({success, message, task_id, addrobj, release})"
//	@Failure		400	"Malformed addrobj, or several live addresses without ?address="
//	@Failure		404	"Address object not found ({error, details})"
//	@Router			/network/addresses/{addrobj} [delete]
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
	}, &addressTaskResponse{
		Message: "IP address deletion task created for " + addrobj,
		Release: &release,
	})
}

// handleNetworkAddressAction serves PUT /network/addresses/{rest...} — the
// enable/disable verbs split from the one wildcard here.
//
//	@Summary		Enable an address's interface (task)
//	@Description	Minimum role: operator. Queues enable_ip_address. HONESTY, loud: no platform here has illumos's per-address enable — the toggle applies to the INTERFACE the addrobj names (netsh set interface / `ip link set up` / ifconfig up), affecting every address on it; the 202 body and the task output both say so. (Route mechanics: one PUT wildcard under /network/addresses/ splits the enable/disable suffix — Go 1.22 ServeMux forbids literal segments after a trailing wildcard.)
//	@Tags			Host Configuration
//	@Produce		json
//	@Param			addrobj	path	string	true	"The listing's addrobj value — may carry a slash (<interface>/v4)"
//	@Success		202	{object}	addressTaskResponse	"Enable task queued ({success, message, task_id, addrobj, note})"
//	@Failure		400	"Malformed addrobj"
//	@Failure		404	"Unknown action suffix"
//	@Router			/network/addresses/{addrobj}/enable [put]
//	@Router			/network/addresses/{addrobj}/disable [put]
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
	s.queueAddressTask(w, r, operation, &netaddr.Metadata{AddrObj: addrobj}, &addressTaskResponse{
		Message: "IP address " + action + " task created for " + addrobj,
		Note:    "no per-address enable exists on " + runtime.GOOS + " — the toggle applies to interface " + iface + " itself",
	})
}
