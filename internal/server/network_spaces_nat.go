package server

import (
	"context"
	"log/slog"
	"net/http"
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

// natLoopbackBody is one loopback mapping on the natnetwork wire — the rule
// string verbatim (the listing's own form).
type natLoopbackBody struct {
	Rule string `json:"rule"`
	IPv6 bool   `json:"ipv6"`
}

// handleCreateNATNetwork serves POST /network/spaces/natnetwork.
func (s *Server) handleCreateNATNetwork(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	var body struct {
		Name    string `json:"name"`
		CIDR    string `json:"cidr"`
		Enabled *bool  `json:"enabled"`
		DHCP    *bool  `json:"dhcp"`
		IPv6    *bool  `json:"ipv6"`
	}
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
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"success": true,
		"name":    body.Name,
		"message": "NAT network " + body.Name + " created",
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

// handleModifyNATNetwork serves PUT /network/spaces/natnetwork/{name} —
// converge the knobs and apply port-forward/loopback rule changes (removes
// first, so a rule can be replaced in one call).
func (s *Server) handleModifyNATNetwork(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name, found := s.findNATNetwork(w, r, exe)
	if !found {
		return
	}
	var body struct {
		CIDR               string           `json:"cidr"`
		Enabled            *bool            `json:"enabled"`
		DHCP               *bool            `json:"dhcp"`
		IPv6               *bool            `json:"ipv6"`
		AddPortForwards    []natForwardBody `json:"add_port_forwards"`
		RemovePortForwards []struct {
			Name string `json:"name"`
			IPv6 bool   `json:"ipv6"`
		} `json:"remove_port_forwards"`
		AddLoopbacks    []natLoopbackBody `json:"add_loopbacks"`
		RemoveLoopbacks []natLoopbackBody `json:"remove_loopbacks"`
	}
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
		if loopback.Rule == "" {
			taskError(w, http.StatusBadRequest, "loopback entries need rule")
			return
		}
	}
	for _, loopback := range body.RemoveLoopbacks {
		if loopback.Rule == "" {
			taskError(w, http.StatusBadRequest, "loopback entries need rule")
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
		if err := vbox.RemoveNATNetworkLoopback(r.Context(), exe, name, remove.IPv6, remove.Rule); err != nil {
			slog.Error("remove nat network loopback", "name", name, "rule", remove.Rule, "error", err)
			taskError(w, http.StatusInternalServerError,
				"Failed to remove loopback "+remove.Rule+": "+err.Error())
			return
		}
	}
	for _, add := range body.AddLoopbacks {
		if err := vbox.AddNATNetworkLoopback(r.Context(), exe, name, add.IPv6, add.Rule); err != nil {
			slog.Error("add nat network loopback", "name", name, "rule", add.Rule, "error", err)
			taskError(w, http.StatusInternalServerError,
				"Failed to add loopback "+add.Rule+": "+err.Error())
			return
		}
	}
	slog.Info("nat network modified", "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "NAT network " + name + " updated",
	})
}

// handleDeleteNATNetwork serves DELETE /network/spaces/natnetwork/{name}.
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
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "NAT network " + name + " removed",
	})
}

// handleStartNATNetwork / handleStopNATNetwork serve POST
// /network/spaces/natnetwork/{name}/start|stop — the service process.
func (s *Server) handleStartNATNetwork(w http.ResponseWriter, r *http.Request) {
	s.natNetworkService(w, r, vbox.StartNATNetwork, "started")
}

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
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "NAT network " + name + " " + past,
	})
}
