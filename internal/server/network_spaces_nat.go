package server

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The NAT-network half of the network-space surface (network_spaces.go holds
// the listing and the host-only families): create/modify/delete/start/stop
// plus port-forward and loopback rule management.

// natForwardBody is one port-forward rule on the natnetwork wire (ipv6
// selects the rule family).
type natForwardBody struct {
	vbox.NATNetworkForward
	IPv6 bool `json:"ipv6"`
}

// natLoopbackBody is one loopback mapping on the natnetwork wire — structured
// (the cross-agent structured-JSON convergence): the host loopback address
// and its offset into the NAT network's range; the agent renders VirtualBox's
// own "address=offset" rule form itself.
type natLoopbackBody struct {
	Address string `json:"address"`
	Offset  int    `json:"offset"`
	IPv6    bool   `json:"ipv6"`
}

// rule renders the VBoxManage loopback rule vocabulary.
func (b *natLoopbackBody) rule() string {
	return b.Address + "=" + strconv.Itoa(b.Offset)
}

// natForwardRemoveBody names one port-forward rule to drop on the natnetwork
// wire (ipv6 selects the rule family).
type natForwardRemoveBody struct {
	Name string `json:"name"`
	IPv6 bool   `json:"ipv6"`
}

// natNetworkResponse is the create/modify/delete/start/stop answer — the small
// {success, name, message} envelope.
type natNetworkResponse struct {
	Success bool   `json:"success"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// natNetworkCreateRequest is POST /network/spaces/natnetwork's body.
type natNetworkCreateRequest struct {
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	Enabled *bool  `json:"enabled"`
	DHCP    *bool  `json:"dhcp"`
	IPv6    *bool  `json:"ipv6"`
}

// handleCreateNATNetwork serves POST /network/spaces/natnetwork.
//
//	@Summary		Create a NAT network
//	@Description	Minimum role: operator. VBoxManage natnetwork add: name + cidr required; enabled defaults true; dhcp/ipv6 toggle the built-in DHCP server and IPv6 support.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			request	body	natNetworkCreateRequest	true	"NAT network to create"
//	@Success		201	{object}	natNetworkResponse	"NAT network created ({success, name, message})"
//	@Failure		400	"Missing name or cidr"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/natnetwork [post]
func (s *Server) handleCreateNATNetwork(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	var body natNetworkCreateRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" || body.CIDR == "" {
		taskError(w, http.StatusBadRequest, "name and cidr are required")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if err := vbox.AddNATNetwork(r.Context(), exe, body.Name, vbox.NATNetworkOptions{
		CIDR:    body.CIDR,
		Enabled: &enabled,
		DHCP:    body.DHCP,
		IPv6:    body.IPv6,
	}); err != nil {
		slog.Error("add nat network", "name", body.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create NAT network: "+err.Error())
		return
	}
	slog.Info("nat network created", "name", body.Name, "cidr", body.CIDR,
		"by", auth.FromContext(r.Context()).Name)
	writeJSONStatus(w, http.StatusCreated, natNetworkResponse{
		Success: true,
		Name:    body.Name,
		Message: "NAT network " + body.Name + " created",
	})
}

// findNATNetwork answers the row or writes the 404.
func (s *Server) findNATNetwork(w http.ResponseWriter, r *http.Request, exe string) (string, bool) {
	name := r.PathValue("name")
	list, err := vbox.ListNATNetworks(r.Context(), exe)
	if err != nil {
		slog.Error("list nat networks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to resolve NAT network")
		return "", false
	}
	for i := range list {
		if list[i].Name == name {
			return name, true
		}
	}
	taskError(w, http.StatusNotFound, "No NAT network named "+name)
	return "", false
}

// natNetworkModifyRequest is PUT /network/spaces/natnetwork/{name}'s body —
// knob changes plus port-forward and loopback rule add/remove lists.
type natNetworkModifyRequest struct {
	CIDR               string                 `json:"cidr"`
	Enabled            *bool                  `json:"enabled"`
	DHCP               *bool                  `json:"dhcp"`
	IPv6               *bool                  `json:"ipv6"`
	AddPortForwards    []natForwardBody       `json:"add_port_forwards"`
	RemovePortForwards []natForwardRemoveBody `json:"remove_port_forwards"`
	AddLoopbacks       []natLoopbackBody      `json:"add_loopbacks"`
	RemoveLoopbacks    []natLoopbackBody      `json:"remove_loopbacks"`
}

// handleModifyNATNetwork serves PUT /network/spaces/natnetwork/{name} —
// converge the knobs and apply port-forward/loopback rule changes (removes
// first, so a rule can be replaced in one call).
//
//	@Summary		Modify a NAT network
//	@Description	Minimum role: operator. Converges the sent knobs (cidr, enabled, dhcp, ipv6 — natnetwork modify) and applies rule changes, removes before adds so one call replaces a rule: port forwards (add_port_forwards[] {name, protocol tcp|udp (default tcp), host_ip?, host_port, guest_ip, guest_port, ipv6? (rule family, default IPv4)} / remove_port_forwards[] {name, ipv6?}) and loopback mappings (add_loopbacks[]/remove_loopbacks[] {address, offset, ipv6?} — structured rows, the cross-agent structured-JSON convergence; the agent renders VirtualBox's own address=offset rule itself, and the listing's loopback_mappings answers the same structured shape back). At least one change is required.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			name	path	string	true	"The NAT network name"
//	@Param			request	body	natNetworkModifyRequest	true	"Knobs and rule changes to apply"
//	@Success		200	{object}	natNetworkResponse	"NAT network updated"
//	@Failure		400	"Nothing to change, or an invalid rule entry"
//	@Failure		404	"No NAT network by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/natnetwork/{name} [put]
func (s *Server) handleModifyNATNetwork(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name, found := s.findNATNetwork(w, r, exe)
	if !found {
		return
	}
	var body natNetworkModifyRequest
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.CIDR == "" && body.Enabled == nil && body.DHCP == nil && body.IPv6 == nil &&
		len(body.AddPortForwards) == 0 && len(body.RemovePortForwards) == 0 &&
		len(body.AddLoopbacks) == 0 && len(body.RemoveLoopbacks) == 0 {
		taskError(w, http.StatusBadRequest, "Nothing to change")
		return
	}
	for _, loopback := range body.AddLoopbacks {
		if loopback.Address == "" || loopback.Offset <= 0 {
			taskError(w, http.StatusBadRequest, "loopback entries need address and offset")
			return
		}
	}
	for _, loopback := range body.RemoveLoopbacks {
		if loopback.Address == "" || loopback.Offset <= 0 {
			taskError(w, http.StatusBadRequest, "loopback entries need address and offset")
			return
		}
	}
	for _, fw := range body.AddPortForwards {
		if fw.Name == "" || fw.HostPort < 1 || fw.GuestPort < 1 {
			taskError(w, http.StatusBadRequest, "add_port_forwards entries need name, host_port, and guest_port")
			return
		}
		switch strings.ToLower(fw.Protocol) {
		case "", "tcp", "udp":
		default:
			taskError(w, http.StatusBadRequest, "add_port_forwards protocol must be tcp or udp")
			return
		}
	}

	if body.CIDR != "" || body.Enabled != nil || body.DHCP != nil || body.IPv6 != nil {
		if err := vbox.ModifyNATNetwork(r.Context(), exe, name, vbox.NATNetworkOptions{
			CIDR:    body.CIDR,
			Enabled: body.Enabled,
			DHCP:    body.DHCP,
			IPv6:    body.IPv6,
		}); err != nil {
			slog.Error("modify nat network", "name", name, "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to modify NAT network: "+err.Error())
			return
		}
	}
	for _, remove := range body.RemovePortForwards {
		if remove.Name == "" {
			taskError(w, http.StatusBadRequest, "remove_port_forwards entries need name")
			return
		}
		if err := vbox.RemoveNATNetworkForward(r.Context(), exe, name, remove.Name, remove.IPv6); err != nil {
			slog.Error("remove nat network forward", "name", name, "rule", remove.Name, "error", err)
			taskError(w, http.StatusInternalServerError,
				"Failed to remove port forward "+remove.Name+": "+err.Error())
			return
		}
	}
	for _, add := range body.AddPortForwards {
		rule := add.NATNetworkForward
		if rule.Protocol == "" {
			rule.Protocol = "tcp"
		}
		rule.Protocol = strings.ToLower(rule.Protocol)
		if err := vbox.AddNATNetworkForward(r.Context(), exe, name, add.IPv6, &rule); err != nil {
			slog.Error("add nat network forward", "name", name, "rule", rule.Name, "error", err)
			taskError(w, http.StatusInternalServerError,
				"Failed to add port forward "+rule.Name+": "+err.Error())
			return
		}
	}
	for _, remove := range body.RemoveLoopbacks {
		if err := vbox.RemoveNATNetworkLoopback(r.Context(), exe, name, remove.IPv6, remove.rule()); err != nil {
			slog.Error("remove nat network loopback", "name", name, "rule", remove.rule(), "error", err)
			taskError(w, http.StatusInternalServerError,
				"Failed to remove loopback "+remove.rule()+": "+err.Error())
			return
		}
	}
	for _, add := range body.AddLoopbacks {
		if err := vbox.AddNATNetworkLoopback(r.Context(), exe, name, add.IPv6, add.rule()); err != nil {
			slog.Error("add nat network loopback", "name", name, "rule", add.rule(), "error", err)
			taskError(w, http.StatusInternalServerError,
				"Failed to add loopback "+add.rule()+": "+err.Error())
			return
		}
	}
	slog.Info("nat network modified", "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, natNetworkResponse{
		Success: true,
		Name:    name,
		Message: "NAT network " + name + " updated",
	})
}

// handleDeleteNATNetwork serves DELETE /network/spaces/natnetwork/{name}.
//
//	@Summary		Remove a NAT network
//	@Description	Minimum role: operator. VBoxManage natnetwork remove. Machines whose adapters name the network lose their uplink — VirtualBox does not refuse.
//	@Tags			Host Configuration
//	@Produce		json
//	@Param			name	path	string	true	"The NAT network name"
//	@Success		200	{object}	natNetworkResponse	"NAT network removed"
//	@Failure		404	"No NAT network by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/natnetwork/{name} [delete]
func (s *Server) handleDeleteNATNetwork(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name, found := s.findNATNetwork(w, r, exe)
	if !found {
		return
	}
	if err := vbox.RemoveNATNetwork(r.Context(), exe, name); err != nil {
		slog.Error("remove nat network", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to remove NAT network: "+err.Error())
		return
	}
	slog.Info("nat network removed", "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, natNetworkResponse{
		Success: true,
		Name:    name,
		Message: "NAT network " + name + " removed",
	})
}

// handleStartNATNetwork / handleStopNATNetwork serve POST
// /network/spaces/natnetwork/{name}/start|stop — the service process.
//
//	@Summary		Start a NAT network's service
//	@Description	Minimum role: operator. VBoxManage natnetwork start — the network's NAT service process (an enabled network normally starts with its first attached VM; this is the explicit control).
//	@Tags			Host Configuration
//	@Produce		json
//	@Param			name	path	string	true	"The NAT network name"
//	@Success		200	{object}	natNetworkResponse	"Service started"
//	@Failure		404	"No NAT network by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/natnetwork/{name}/start [post]
func (s *Server) handleStartNATNetwork(w http.ResponseWriter, r *http.Request) {
	s.natNetworkService(w, r, vbox.StartNATNetwork, "started")
}

// @Summary		Stop a NAT network's service
// @Description	Minimum role: operator. VBoxManage natnetwork stop — attached running machines lose connectivity until it starts again.
// @Tags			Host Configuration
// @Produce		json
// @Param			name	path	string	true	"The NAT network name"
// @Success		200	{object}	natNetworkResponse	"Service stopped"
// @Failure		404	"No NAT network by that name"
// @Failure		503	"VirtualBox is not installed"
// @Router			/network/spaces/natnetwork/{name}/stop [post]
func (s *Server) handleStopNATNetwork(w http.ResponseWriter, r *http.Request) {
	s.natNetworkService(w, r, vbox.StopNATNetwork, "stopped")
}

func (s *Server) natNetworkService(w http.ResponseWriter, r *http.Request,
	verb func(ctx context.Context, vboxManage, name string) error, past string,
) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name, found := s.findNATNetwork(w, r, exe)
	if !found {
		return
	}
	if err := verb(r.Context(), exe, name); err != nil {
		slog.Error("nat network service", "name", name, "action", past, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed: "+err.Error())
		return
	}
	slog.Info("nat network "+past, "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, natNetworkResponse{
		Success: true,
		Name:    name,
		Message: "NAT network " + name + " " + past,
	})
}
