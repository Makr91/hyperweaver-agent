package server

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The network-space surface (/network/spaces*, the network-spaces capability
// token — the UI topology ask, sync 2026-07-19): enumerate and manage
// VirtualBox's network spaces. This file holds the listing and the host-only
// families (interfaces with their DHCP servers, plus the 7.x vmnet host-only
// networks); network_spaces_nat.go holds the NAT-network half. Internal
// networks are read-only — VirtualBox has no intnet verbs, they exist while
// a VM references them. GET is viewer, mutations operator (the central
// policy's defaults). VirtualBox-only: utm machines join no spaces.

// handleListNetworkSpaces serves GET /network/spaces — every network space
// as one typed row (the topology mapper's network-card feed).
func (s *Server) handleListNetworkSpaces(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}

	hostonly, err := vbox.ListHostOnlyIfs(r.Context(), exe)
	if err != nil {
		slog.Error("list hostonly interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list network spaces")
		return
	}
	intnets, err := vbox.ListIntNets(r.Context(), exe)
	if err != nil {
		slog.Error("list internal networks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list network spaces")
		return
	}
	natnets, err := vbox.ListNATNetworks(r.Context(), exe)
	if err != nil {
		slog.Error("list nat networks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list network spaces")
		return
	}
	// The DHCP join is best-effort: hostonly rows still render without it.
	dhcpServers, err := vbox.ListDHCPServers(r.Context(), exe)
	if err != nil {
		slog.Warn("list dhcp servers", "error", err)
		dhcpServers = nil
	}
	// Best-effort too: `list hostonlynets` predates nothing on 7.x but older
	// VBoxManage builds lack the verb — their hosts simply have no such rows.
	hostonlyNets, err := vbox.ListHostOnlyNets(r.Context(), exe)
	if err != nil {
		slog.Warn("list hostonly networks", "error", err)
		hostonlyNets = nil
	}

	spaces := []map[string]any{}
	for i := range hostonly {
		iface := &hostonly[i]
		dhcp := map[string]any{"exists": false, "enabled": false}
		for j := range dhcpServers {
			if dhcpServers[j].NetworkName == iface.VBoxNetworkName {
				dhcp = map[string]any{
					"exists":    true,
					"enabled":   dhcpServers[j].Enabled,
					"server_ip": dhcpServers[j].ServerIP,
					"lower_ip":  dhcpServers[j].LowerIP,
					"upper_ip":  dhcpServers[j].UpperIP,
				}
				break
			}
		}
		spaces = append(spaces, map[string]any{
			"type":              "hostonly",
			"name":              iface.Name,
			"ip_address":        iface.IPAddress,
			"network_mask":      iface.NetworkMask,
			"vbox_network_name": iface.VBoxNetworkName,
			"dhcp":              dhcp,
		})
	}
	for i := range hostonlyNets {
		net := &hostonlyNets[i]
		row := map[string]any{
			"type":              "hostonlynet",
			"name":              net.Name,
			"network_mask":      net.NetworkMask,
			"lower_ip":          net.LowerIP,
			"upper_ip":          net.UpperIP,
			"vbox_network_name": net.VBoxNetworkName,
			"enabled":           net.Enabled,
		}
		if net.GUID != "" {
			row["guid"] = net.GUID
		}
		spaces = append(spaces, row)
	}
	for _, name := range intnets {
		spaces = append(spaces, map[string]any{"type": "intnet", "name": name})
	}
	for i := range natnets {
		nat := &natnets[i]
		forwards := []map[string]any{}
		for j := range nat.PortForwards4 {
			forwards = append(forwards, natForwardRow(&nat.PortForwards4[j], false))
		}
		for j := range nat.PortForwards6 {
			forwards = append(forwards, natForwardRow(&nat.PortForwards6[j], true))
		}
		row := map[string]any{
			"type":          "natnetwork",
			"name":          nat.Name,
			"cidr":          nat.CIDR,
			"gateway":       nat.Gateway,
			"enabled":       nat.Enabled,
			"dhcp_enabled":  nat.DHCPEnabled,
			"ipv6":          nat.IPv6,
			"port_forwards": forwards,
		}
		if nat.IPv6Prefix != "" {
			row["ipv6_prefix"] = nat.IPv6Prefix
		}
		if len(nat.LoopbackMappings) > 0 {
			row["loopback_mappings"] = nat.LoopbackMappings
		}
		spaces = append(spaces, row)
	}

	writeJSON(w, map[string]any{"spaces": spaces, "total": len(spaces)})
}

func natForwardRow(fw *vbox.NATNetworkForward, ipv6 bool) map[string]any {
	return map[string]any{
		"name":       fw.Name,
		"protocol":   fw.Protocol,
		"host_ip":    fw.HostIP,
		"host_port":  fw.HostPort,
		"guest_ip":   fw.GuestIP,
		"guest_port": fw.GuestPort,
		"ipv6":       ipv6,
	}
}

// requireVBox answers the exe path or writes the 503.
func (s *Server) requireVBox(w http.ResponseWriter, r *http.Request) string {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
	}
	return exe
}

// hostOnlyDHCPBody is the hostonly create/modify dhcp sub-document.
type hostOnlyDHCPBody struct {
	ServerIP string `json:"server_ip"`
	Netmask  string `json:"netmask"`
	LowerIP  string `json:"lower_ip"`
	UpperIP  string `json:"upper_ip"`
}

func (d *hostOnlyDHCPBody) valid() bool {
	return d.ServerIP != "" && d.LowerIP != "" && d.UpperIP != ""
}

func (d *hostOnlyDHCPBody) netmaskOr(fallback string) string {
	if d.Netmask != "" {
		return d.Netmask
	}
	return fallback
}

func findHostOnlyByName(list []vbox.HostOnlyIf, name string) *vbox.HostOnlyIf {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

// handleCreateHostOnlySpace serves POST /network/spaces/hostonly — create a
// host-only interface (VirtualBox assigns its name), optionally configure
// its static IP and add its DHCP server in one call. A failed follow-up step
// names the already-created interface — it is NOT rolled back.
func (s *Server) handleCreateHostOnlySpace(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	var body struct {
		IP      string            `json:"ip"`
		Netmask string            `json:"netmask"`
		DHCP    *hostOnlyDHCPBody `json:"dhcp"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.DHCP != nil && !body.DHCP.valid() {
		taskError(w, http.StatusBadRequest, "dhcp needs server_ip, lower_ip, and upper_ip")
		return
	}
	netmask := body.Netmask
	if netmask == "" {
		netmask = "255.255.255.0"
	}

	name, err := vbox.CreateHostOnlyIf(r.Context(), exe)
	if err != nil {
		slog.Error("create hostonly interface", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create host-only interface: "+err.Error())
		return
	}
	if body.IP != "" {
		if cerr := vbox.ConfigureHostOnlyIf(r.Context(), exe, name, body.IP, netmask); cerr != nil {
			slog.Error("configure hostonly interface", "interface", name, "error", cerr)
			taskError(w, http.StatusInternalServerError,
				"Interface "+name+" was created but configuring "+body.IP+" failed: "+cerr.Error())
			return
		}
	}
	if body.DHCP != nil {
		if derr := vbox.AddDHCPServer(r.Context(), exe, name, body.DHCP.ServerIP,
			body.DHCP.netmaskOr(netmask), body.DHCP.LowerIP, body.DHCP.UpperIP); derr != nil {
			slog.Error("add hostonly dhcp server", "interface", name, "error", derr)
			taskError(w, http.StatusInternalServerError,
				"Interface "+name+" was created but its DHCP server failed: "+derr.Error())
			return
		}
	}
	slog.Info("hostonly network space created", "interface", name,
		"ip", body.IP, "by", auth.FromContext(r.Context()).Name)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"success": true,
		"name":    name,
		"message": "Host-only interface " + name + " created",
	})
}

// handleModifyHostOnlySpace serves PUT /network/spaces/hostonly/{name} —
// reconfigure the static IP and/or the DHCP server (dhcp: null REMOVES the
// server; an absent dhcp key leaves it alone).
func (s *Server) handleModifyHostOnlySpace(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name := r.PathValue("name")
	list, err := vbox.ListHostOnlyIfs(r.Context(), exe)
	if err != nil {
		slog.Error("list hostonly interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to resolve host-only interface")
		return
	}
	iface := findHostOnlyByName(list, name)
	if iface == nil {
		taskError(w, http.StatusNotFound, "No host-only interface named "+name)
		return
	}

	var body struct {
		IP      string          `json:"ip"`
		Netmask string          `json:"netmask"`
		DHCP    json.RawMessage `json:"dhcp"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.IP == "" && body.DHCP == nil {
		taskError(w, http.StatusBadRequest, "Nothing to change: send ip (with netmask) and/or dhcp")
		return
	}

	netmask := body.Netmask
	if netmask == "" {
		netmask = iface.NetworkMask
	}
	if netmask == "" {
		netmask = "255.255.255.0"
	}
	if body.IP != "" {
		if cerr := vbox.ConfigureHostOnlyIf(r.Context(), exe, name, body.IP, netmask); cerr != nil {
			slog.Error("configure hostonly interface", "interface", name, "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to configure "+name+": "+cerr.Error())
			return
		}
	}

	if body.DHCP != nil {
		if string(body.DHCP) == "null" {
			if rerr := vbox.RemoveDHCPServer(r.Context(), exe, name); rerr != nil {
				// Absent servers refuse — tolerated, the end state matches.
				slog.Warn("remove hostonly dhcp server", "interface", name, "error", rerr)
			}
		} else {
			var dhcp hostOnlyDHCPBody
			if uerr := json.Unmarshal(body.DHCP, &dhcp); uerr != nil || !dhcp.valid() {
				taskError(w, http.StatusBadRequest, "dhcp needs server_ip, lower_ip, and upper_ip (or null to remove)")
				return
			}
			existing, derr := machines.FindProvisioningDHCP(r.Context(), exe, iface.VBoxNetworkName)
			if derr != nil {
				slog.Error("list dhcp servers", "error", derr)
				taskError(w, http.StatusInternalServerError, "Failed to resolve the DHCP server")
				return
			}
			apply := vbox.AddDHCPServer
			if existing != nil {
				apply = vbox.ModifyDHCPServer
			}
			if aerr := apply(r.Context(), exe, name, dhcp.ServerIP,
				dhcp.netmaskOr(netmask), dhcp.LowerIP, dhcp.UpperIP); aerr != nil {
				slog.Error("apply hostonly dhcp server", "interface", name, "error", aerr)
				taskError(w, http.StatusInternalServerError, "Failed to apply the DHCP server: "+aerr.Error())
				return
			}
		}
	}
	slog.Info("hostonly network space modified", "interface", name,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "Host-only interface " + name + " updated",
	})
}

// handleDeleteHostOnlySpace serves DELETE /network/spaces/hostonly/{name} —
// DHCP server first (tolerantly), then the interface (the teardown order).
func (s *Server) handleDeleteHostOnlySpace(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name := r.PathValue("name")
	list, err := vbox.ListHostOnlyIfs(r.Context(), exe)
	if err != nil {
		slog.Error("list hostonly interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to resolve host-only interface")
		return
	}
	if findHostOnlyByName(list, name) == nil {
		taskError(w, http.StatusNotFound, "No host-only interface named "+name)
		return
	}
	if rerr := vbox.RemoveDHCPServer(r.Context(), exe, name); rerr != nil {
		slog.Warn("remove hostonly dhcp server", "interface", name, "error", rerr)
	}
	if rerr := vbox.RemoveHostOnlyIf(r.Context(), exe, name); rerr != nil {
		slog.Error("remove hostonly interface", "interface", name, "error", rerr)
		taskError(w, http.StatusInternalServerError, "Failed to remove "+name+": "+rerr.Error())
		return
	}
	slog.Info("hostonly network space removed", "interface", name,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "Host-only interface " + name + " removed",
	})
}

// handleCreateHostOnlyNet serves POST /network/spaces/hostonlynet — create a
// host-only NETWORK (VirtualBox 7's vmnet-backed family; the caller names
// it, unlike interfaces).
func (s *Server) handleCreateHostOnlyNet(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	var body struct {
		Name    string `json:"name"`
		Netmask string `json:"netmask"`
		LowerIP string `json:"lower_ip"`
		UpperIP string `json:"upper_ip"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" || body.Netmask == "" || body.LowerIP == "" || body.UpperIP == "" {
		taskError(w, http.StatusBadRequest, "name, netmask, lower_ip, and upper_ip are required")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if err := vbox.AddHostOnlyNet(r.Context(), exe, body.Name, vbox.HostOnlyNetOptions{
		Netmask: body.Netmask,
		LowerIP: body.LowerIP,
		UpperIP: body.UpperIP,
		Enabled: &enabled,
	}); err != nil {
		slog.Error("add hostonly network", "name", body.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to create host-only network: "+err.Error())
		return
	}
	slog.Info("hostonly network created", "name", body.Name,
		"by", auth.FromContext(r.Context()).Name)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"success": true,
		"name":    body.Name,
		"message": "Host-only network " + body.Name + " created",
	})
}

// findHostOnlyNet answers the name or writes the 404.
func (s *Server) findHostOnlyNet(w http.ResponseWriter, r *http.Request, exe string) (string, bool) {
	name := r.PathValue("name")
	list, err := vbox.ListHostOnlyNets(r.Context(), exe)
	if err != nil {
		slog.Error("list hostonly networks", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to resolve host-only network")
		return "", false
	}
	for i := range list {
		if list[i].Name == name {
			return name, true
		}
	}
	taskError(w, http.StatusNotFound, "No host-only network named "+name)
	return "", false
}

// handleModifyHostOnlyNet serves PUT /network/spaces/hostonlynet/{name}.
func (s *Server) handleModifyHostOnlyNet(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name, found := s.findHostOnlyNet(w, r, exe)
	if !found {
		return
	}
	var body struct {
		Netmask string `json:"netmask"`
		LowerIP string `json:"lower_ip"`
		UpperIP string `json:"upper_ip"`
		Enabled *bool  `json:"enabled"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Netmask == "" && body.LowerIP == "" && body.UpperIP == "" && body.Enabled == nil {
		taskError(w, http.StatusBadRequest, "Nothing to change")
		return
	}
	if err := vbox.ModifyHostOnlyNet(r.Context(), exe, name, vbox.HostOnlyNetOptions{
		Netmask: body.Netmask,
		LowerIP: body.LowerIP,
		UpperIP: body.UpperIP,
		Enabled: body.Enabled,
	}); err != nil {
		slog.Error("modify hostonly network", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to modify host-only network: "+err.Error())
		return
	}
	slog.Info("hostonly network modified", "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "Host-only network " + name + " updated",
	})
}

// handleDeleteHostOnlyNet serves DELETE /network/spaces/hostonlynet/{name}.
func (s *Server) handleDeleteHostOnlyNet(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	name, found := s.findHostOnlyNet(w, r, exe)
	if !found {
		return
	}
	if err := vbox.RemoveHostOnlyNet(r.Context(), exe, name); err != nil {
		slog.Error("remove hostonly network", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to remove host-only network: "+err.Error())
		return
	}
	slog.Info("hostonly network removed", "name", name, "by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success": true,
		"name":    name,
		"message": "Host-only network " + name + " removed",
	})
}
