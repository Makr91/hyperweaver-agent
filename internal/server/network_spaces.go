package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
	"sync"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// hostOnlyNetsNarrated keeps the hostonlynet best-effort failure to ONE log
// line per process — the listing is polled by the UI topology page.
var hostOnlyNetsNarrated sync.Once

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
//
//	@Summary		List the host's VirtualBox network spaces
//	@Description	Minimum role: viewer (the network-spaces capability token, minted 2026-07-19 — the UI topology mapper's network-card feed; devices.nics rows join here by their network field). One typed row per space: hostonly = a host-only INTERFACE (VBoxManage list hostonlyifs; VirtualBox assigns names itself) with its DHCP server joined by VBoxNetworkName (best-effort — a failed dhcpservers read degrades to {exists:false} rows, narrated in the log); hostonlynet = a host-only NETWORK (list hostonlynets — VirtualBox's macOS-ONLY vmnet family; Oracle's platform split: VirtualBox 7 on macOS REMOVED host-only adapters while every other host OS lacks the hostonlynet verb entirely, so darwin agents carry hostonlynet rows, every other host carries hostonly rows, and off darwin the verb is never even probed); intnet = an implicit internal network (list intnets — exists while a VM references it, no other attributes); natnetwork = a NAT network (list natnetworks) with its port-forward rules (IPv4 + IPv6 folded into one port_forwards[] with an ipv6 flag) and loopback mappings (structured rows — the listing's "address=offset" rules parsed into {address, offset, ipv6}; the cross-agent structured-JSON convergence). VirtualBox-only — utm machines join no spaces.
//	@Tags			Host Configuration
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"The network spaces"
//	@Failure		500	"A VBoxManage listing failed"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces [get]
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
	// hostonlynet is VirtualBox's macOS-ONLY family (Oracle's ruling: every
	// other host OS uses host-only interfaces) — off darwin the verb does not
	// exist, so no probe and no rows. A darwin failure narrates once.
	var hostonlyNets []vbox.HostOnlyNet
	if runtime.GOOS == "darwin" {
		hostonlyNets, err = vbox.ListHostOnlyNets(r.Context(), exe)
		if err != nil {
			hostOnlyNetsNarrated.Do(func() {
				slog.Warn("list hostonly networks failed — no hostonlynet rows render (narrated once; the UI polls this endpoint)",
					"error", err)
			})
			hostonlyNets = nil
		}
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

// requireHostOnlyIfPlatform writes the platform refusal ON darwin —
// VirtualBox 7 on macOS REMOVED host-only adapters (startvm errors
// "Host-only adapters are no longer supported!"; hostonlynet replaced the
// family there — Oracle's platform split, the mirror of
// requireHostOnlyNetPlatform). False = response already written.
func requireHostOnlyIfPlatform(w http.ResponseWriter) bool {
	if runtime.GOOS != "darwin" {
		return true
	}
	taskError(w, http.StatusBadRequest,
		"host-only interfaces died with VirtualBox 7 on macOS — this host manages host-only networks instead (/network/spaces/hostonlynet)")
	return false
}

// hostOnlySpaceResponse is the host-only families' mutation answer —
// {success, name, message}.
type hostOnlySpaceResponse struct {
	Success bool   `json:"success"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// hostOnlySpaceCreateRequest is POST /network/spaces/hostonly's body.
type hostOnlySpaceCreateRequest struct {
	IP      string `json:"ip"`
	Netmask string `json:"netmask"`
	// {server_ip, lower_ip, upper_ip, netmask?} to add in the same call
	DHCP *hostOnlyDHCPBody `json:"dhcp"`
}

// handleCreateHostOnlySpace serves POST /network/spaces/hostonly — create a
// host-only interface (VirtualBox assigns its name), optionally configure
// its static IP and add its DHCP server in one call. A failed follow-up step
// names the already-created interface — it is NOT rolled back.
//
//	@Summary		Create a host-only interface
//	@Description	Minimum role: operator. VBoxManage hostonlyif create — VirtualBox assigns the interface name (the answer carries it); the request may configure the static IPv4 (ip + netmask, netmask defaulting to 255.255.255.0) and add the interface's DHCP server (dhcp {server_ip, lower_ip, upper_ip, netmask?}) in the same call. A failed follow-up step answers 500 NAMING the already-created interface — it is not rolled back (delete it explicitly if unwanted). Windows hosts may need driver-install privileges — VirtualBox's own error rides through. macOS hosts REFUSE the whole hostonly-interface family with a 400 (VirtualBox 7 removed host-only adapters there — manage /network/spaces/hostonlynet instead).
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			request	body	hostOnlySpaceCreateRequest	false	"Optional static IP and DHCP server"
//	@Success		201	{object}	hostOnlySpaceResponse	"Interface created ({success, name, message})"
//	@Failure		400	"Invalid body, dhcp missing server_ip/lower_ip/upper_ip, or a macOS host (host-only interfaces died with VirtualBox 7 there — use hostonlynet)"
//	@Failure		500	"Creation or a follow-up step failed (the message names the created interface when one exists)"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/hostonly [post]
func (s *Server) handleCreateHostOnlySpace(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	if !requireHostOnlyIfPlatform(w) {
		return
	}
	var body hostOnlySpaceCreateRequest
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
	writeJSONStatus(w, http.StatusCreated, hostOnlySpaceResponse{
		Success: true,
		Name:    name,
		Message: "Host-only interface " + name + " created",
	})
}

// hostOnlySpaceModifyRequest is PUT /network/spaces/hostonly/{name}'s body.
type hostOnlySpaceModifyRequest struct {
	IP      string `json:"ip"`
	Netmask string `json:"netmask"`
	// {server_ip, lower_ip, upper_ip, netmask?} to add/converge; null to remove
	DHCP json.RawMessage `json:"dhcp"`
}

// handleModifyHostOnlySpace serves PUT /network/spaces/hostonly/{name} —
// reconfigure the static IP and/or the DHCP server (dhcp: null REMOVES the
// server; an absent dhcp key leaves it alone).
//
//	@Summary		Reconfigure a host-only interface
//	@Description	Minimum role: operator. ip (+ netmask, defaulting to the interface's current mask) reassigns the static IPv4 (hostonlyif ipconfig); dhcp {server_ip, lower_ip, upper_ip, netmask?} adds or converges the interface's DHCP server; dhcp: null REMOVES the server (an absent dhcp key leaves it alone). At least one of ip/dhcp is required.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			name	path	string	true	"The interface name from GET /network/spaces (URL-encode spaces)"
//	@Param			request	body	hostOnlySpaceModifyRequest	true	"IP and/or DHCP changes"
//	@Success		200	{object}	hostOnlySpaceResponse	"Interface updated"
//	@Failure		400	"Nothing to change, an invalid dhcp document, or a macOS host (use hostonlynet)"
//	@Failure		404	"No host-only interface by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/hostonly/{name} [put]
func (s *Server) handleModifyHostOnlySpace(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	if !requireHostOnlyIfPlatform(w) {
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

	var body hostOnlySpaceModifyRequest
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
//
//	@Summary		Remove a host-only interface
//	@Description	Minimum role: operator. The teardown order: the interface's DHCP server first (tolerantly — absence is fine), then hostonlyif remove. Machines still attached to the interface lose their uplink — VirtualBox does not refuse; check GET /network/spaces consumers first.
//	@Tags			Host Configuration
//	@Produce		json
//	@Param			name	path	string	true	"The interface name from GET /network/spaces (URL-encode spaces)"
//	@Success		200	{object}	hostOnlySpaceResponse	"Interface removed"
//	@Failure		400	"A macOS host (use hostonlynet)"
//	@Failure		404	"No host-only interface by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/hostonly/{name} [delete]
func (s *Server) handleDeleteHostOnlySpace(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	if !requireHostOnlyIfPlatform(w) {
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
	writeJSON(w, hostOnlySpaceResponse{
		Success: true,
		Name:    name,
		Message: "Host-only interface " + name + " removed",
	})
}

// requireHostOnlyNetPlatform writes the platform refusal off darwin —
// hostonlynet is VirtualBox's macOS-only family (Oracle's ruling: every other
// host OS uses host-only interfaces). False = response already written.
func requireHostOnlyNetPlatform(w http.ResponseWriter) bool {
	if runtime.GOOS == "darwin" {
		return true
	}
	taskError(w, http.StatusBadRequest,
		"hostonlynet is VirtualBox's macOS-only family — this host manages host-only interfaces instead (/network/spaces/hostonly)")
	return false
}

// hostOnlyNetCreateRequest is POST /network/spaces/hostonlynet's body.
type hostOnlyNetCreateRequest struct {
	Name    string `json:"name"`
	Netmask string `json:"netmask"`
	LowerIP string `json:"lower_ip"`
	UpperIP string `json:"upper_ip"`
	Enabled *bool  `json:"enabled"`
}

// handleCreateHostOnlyNet serves POST /network/spaces/hostonlynet — create a
// host-only NETWORK (VirtualBox 7's vmnet-backed family; the caller names
// it, unlike interfaces).
//
//	@Summary		Create a host-only network
//	@Description	Minimum role: operator. VBoxManage hostonlynet add — VirtualBox's macOS-ONLY vmnet-backed host-only NETWORK family (the caller names it, unlike interfaces): name, netmask, lower_ip, upper_ip required; enabled defaults true. Non-macOS hosts answer 400 (Oracle's platform split — every other host OS lacks the verb; manage /network/spaces/hostonly there).
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			request	body	hostOnlyNetCreateRequest	true	"The network to create"
//	@Success		201	{object}	hostOnlySpaceResponse	"Host-only network created ({success, name, message})"
//	@Failure		400	"Missing name/netmask/lower_ip/upper_ip"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/hostonlynet [post]
func (s *Server) handleCreateHostOnlyNet(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	if !requireHostOnlyNetPlatform(w) {
		return
	}
	var body hostOnlyNetCreateRequest
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
	writeJSONStatus(w, http.StatusCreated, hostOnlySpaceResponse{
		Success: true,
		Name:    body.Name,
		Message: "Host-only network " + body.Name + " created",
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

// hostOnlyNetModifyRequest is PUT /network/spaces/hostonlynet/{name}'s body.
type hostOnlyNetModifyRequest struct {
	Netmask string `json:"netmask"`
	LowerIP string `json:"lower_ip"`
	UpperIP string `json:"upper_ip"`
	Enabled *bool  `json:"enabled"`
}

// handleModifyHostOnlyNet serves PUT /network/spaces/hostonlynet/{name}.
//
//	@Summary		Modify a host-only network
//	@Description	Minimum role: operator. Converges the sent knobs (netmask, lower_ip, upper_ip, enabled — hostonlynet modify). At least one is required.
//	@Tags			Host Configuration
//	@Accept			json
//	@Produce		json
//	@Param			name	path	string	true	"The network name"
//	@Param			request	body	hostOnlyNetModifyRequest	true	"Knobs to converge"
//	@Success		200	{object}	hostOnlySpaceResponse	"Host-only network updated"
//	@Failure		400	"Nothing to change, or a non-macOS host (hostonlynet is VirtualBox's macOS-only family)"
//	@Failure		404	"No host-only network by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/hostonlynet/{name} [put]
func (s *Server) handleModifyHostOnlyNet(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	if !requireHostOnlyNetPlatform(w) {
		return
	}
	name, found := s.findHostOnlyNet(w, r, exe)
	if !found {
		return
	}
	var body hostOnlyNetModifyRequest
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
	writeJSON(w, hostOnlySpaceResponse{
		Success: true,
		Name:    name,
		Message: "Host-only network " + name + " updated",
	})
}

// handleDeleteHostOnlyNet serves DELETE /network/spaces/hostonlynet/{name}.
//
//	@Summary		Remove a host-only network
//	@Description	Minimum role: operator. VBoxManage hostonlynet remove. Machines whose adapters name the network lose their uplink — VirtualBox does not refuse.
//	@Tags			Host Configuration
//	@Produce		json
//	@Param			name	path	string	true	"The network name"
//	@Success		200	{object}	hostOnlySpaceResponse	"Host-only network removed"
//	@Failure		400	"A non-macOS host (hostonlynet is VirtualBox's macOS-only family)"
//	@Failure		404	"No host-only network by that name"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/network/spaces/hostonlynet/{name} [delete]
func (s *Server) handleDeleteHostOnlyNet(w http.ResponseWriter, r *http.Request) {
	exe := s.requireVBox(w, r)
	if exe == "" {
		return
	}
	if !requireHostOnlyNetPlatform(w) {
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
	writeJSON(w, hostOnlySpaceResponse{
		Success: true,
		Name:    name,
		Message: "Host-only network " + name + " removed",
	})
}
