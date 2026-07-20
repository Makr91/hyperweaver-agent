package server

import (
	"log/slog"
	"net/http"
	"runtime"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

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
