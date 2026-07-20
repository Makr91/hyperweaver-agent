package server

import (
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The provisioning-network surface — zoneweaver's
// ProvisioningNetworkController (status / setup / teardown) on VirtualBox:
// ONE host-only interface (the base's etherstub + host VNIC + static IP) and
// VirtualBox's own DHCP server (the base's dhcpd). The base's NAT/forwarding
// pieces translate to the create-time NAT adapter + ssh port-forward
// transport (Mark's architecture 2026-07-07); this surface stays
// dormant-but-available for host-type networks[] entries. Setup and teardown
// queue the base's exact operations; status answers its component-map shape.

// handleProvisioningNetworkStatus mirrors GET /provisioning/network/status:
// the disabled branch is bare {enabled:false, message}; enabled answers
// ready + per-component existence + the effective configuration.
//
//	@Summary		Provisioning network status
//	@Description	Minimum role: viewer. The dedicated provisioning network (the zoneweaver mechanism's etherstub+dhcpd, as ONE VirtualBox host-only interface — identified by provisioning.network.host_ip, since VirtualBox assigns interface names itself — plus its DHCP server). Disabled answers just {enabled:false, message}; enabled answers ready + per-component existence + the effective configuration. macOS hosts (Oracle's split) answer components.network ({name: "hyperweaver-provision", exists}) instead of interface/ip_address, with dhcp {exists, enabled, embedded: true} — the hostonlynet's own embedded range serves DHCP. The base's NAT/forwarding components translate to the create-time NAT adapter + ssh port-forward transport (the provisioning NIC); this host-only machinery stays dormant-but-available for host-type networks[] entries and build-it-yourself setups.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}	"Provisioning network status"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/provisioning/network/status [get]
func (s *Server) handleProvisioningNetworkStatus(w http.ResponseWriter, r *http.Request) {
	network := s.cfg.Provisioning.Network
	if !network.Enabled {
		writeJSON(w, map[string]any{
			"enabled": false,
			"message": "Provisioning network is disabled in configuration",
		})
		return
	}

	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}

	if machines.UseHostOnlyNets() {
		net, nerr := machines.FindProvisioningNet(r.Context(), exe)
		if nerr != nil {
			slog.Error("list host-only networks", "error", nerr)
			taskError(w, http.StatusInternalServerError, "Failed to check provisioning network status")
			return
		}
		writeJSON(w, map[string]any{
			"enabled": true,
			"ready":   net != nil && net.Enabled,
			"components": map[string]any{
				"network": map[string]any{
					"name":   machines.ProvisioningNetName,
					"exists": net != nil,
				},
				"dhcp": map[string]any{
					"exists":   net != nil,
					"enabled":  net != nil && net.Enabled,
					"embedded": true,
				},
			},
			"config": network,
		})
		return
	}

	iface, err := machines.FindProvisioningIf(r.Context(), exe, network.HostIP)
	if err != nil {
		slog.Error("list host-only interfaces", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to check provisioning network status")
		return
	}

	ifaceName := ""
	dhcpExists := false
	dhcpEnabled := false
	if iface != nil {
		ifaceName = iface.Name
		if server, derr := machines.FindProvisioningDHCP(r.Context(), exe, iface.VBoxNetworkName); derr != nil {
			slog.Error("list dhcp servers", "error", derr)
			taskError(w, http.StatusInternalServerError, "Failed to check provisioning network status")
			return
		} else if server != nil {
			dhcpExists = true
			dhcpEnabled = server.Enabled
		}
	}

	writeJSON(w, map[string]any{
		"enabled": true,
		"ready":   iface != nil && dhcpEnabled,
		"components": map[string]any{
			"interface": map[string]any{
				"name":   ifaceName,
				"exists": iface != nil,
			},
			"ip_address": map[string]any{
				"address":    network.HostIP,
				"configured": iface != nil,
			},
			"dhcp": map[string]any{
				"exists":  dhcpExists,
				"enabled": dhcpEnabled,
			},
		},
		"config": network,
	})
}

// networkTaskResponse is the 202 task-queued answer to POST
// /provisioning/network/setup and DELETE /provisioning/network/teardown
// (the acceptedTask shape, typed).
type networkTaskResponse struct {
	Success bool   `json:"success"`
	TaskID  string `json:"task_id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// queueNetworkTask queues one provisioning-network operation as a system
// task (the base's parent container, minus the chained children — this
// agent's whole setup is one executor).
func (s *Server) queueNetworkTask(w http.ResponseWriter, r *http.Request, operation, message string) {
	if !s.cfg.Provisioning.Network.Enabled {
		taskError(w, http.StatusBadRequest, "Provisioning network is disabled in configuration")
		return
	}
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   operation,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   auth.FromContext(r.Context()).Name,
	})
	if err != nil {
		slog.Error("queue provisioning network task", "operation", operation, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue provisioning network task")
		return
	}
	slog.Info("provisioning network task queued", "operation", operation,
		"task_id", task.ID, "by", auth.FromContext(r.Context()).Name)
	writeJSONStatus(w, http.StatusAccepted, networkTaskResponse{
		Success: true,
		TaskID:  task.ID,
		Status:  tasks.StatusPending,
		Message: message,
	})
}

// handleProvisioningNetworkSetup mirrors POST /provisioning/network/setup.
//
//	@Summary		Set up the provisioning network
//	@Description	Minimum role: operator. Queues a provisioning_network_setup task (category-locked — one network mutation at a time), idempotent at every component: the host-only interface is created only when none carries the configured host_ip, its address always converges onto the configuration, and the DHCP server (subnet range, its own dhcp_server_ip) is added or modified to match. Machines with host-type networks[] entries then attach to this interface at create, and each entry's address pins as a per-VM-NIC DHCP fixed lease — the guest's ordinary DHCP request receives the document's own control IP, so wait_ssh dials a deterministic address. macOS hosts (Oracle's split — host-only adapters died with VirtualBox 7 there) create/converge ONE named host-only NETWORK instead: hyperweaver-provision, a hostonlynet whose embedded lower/upper range IS the DHCP (no dhcpserver verbs exist in that family; host_ip is vmnet's to assign, and per-VM fixed leases have no analog — pinned addresses narrate honestly and the networking role applies them in-guest; the pipeline's transport rides the NAT forward regardless). Host-type machines there attach via --nic hostonlynet + --host-only-net.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		202	{object}	networkTaskResponse	"Setup task queued"
//	@Failure		400	"Provisioning network is disabled in configuration"
//	@Router			/provisioning/network/setup [post]
func (s *Server) handleProvisioningNetworkSetup(w http.ResponseWriter, r *http.Request) {
	s.queueNetworkTask(w, r, machines.OpNetworkSetup,
		"Provisioning network setup task queued")
}

// handleProvisioningNetworkTeardown mirrors DELETE
// /provisioning/network/teardown.
//
//	@Summary		Tear down the provisioning network
//	@Description	Minimum role: operator. Queues a provisioning_network_teardown task: the DHCP server first, then the host-only interface (the base's reverse order); absent components are noted, never errors. macOS hosts remove the hyperweaver-provision host-only network instead.
//	@Tags			Provisioning
//	@Produce		json
//	@Success		202	{object}	networkTaskResponse	"Teardown task queued"
//	@Failure		400	"Provisioning network is disabled in configuration"
//	@Router			/provisioning/network/teardown [delete]
func (s *Server) handleProvisioningNetworkTeardown(w http.ResponseWriter, r *http.Request) {
	s.queueNetworkTask(w, r, machines.OpNetworkTeardown,
		"Provisioning network teardown task queued")
}
