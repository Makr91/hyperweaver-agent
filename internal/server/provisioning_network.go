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
	acceptedTask(w, task.ID, message)
}

// handleProvisioningNetworkSetup mirrors POST /provisioning/network/setup.
func (s *Server) handleProvisioningNetworkSetup(w http.ResponseWriter, r *http.Request) {
	s.queueNetworkTask(w, r, machines.OpNetworkSetup,
		"Provisioning network setup task queued")
}

// handleProvisioningNetworkTeardown mirrors DELETE
// /provisioning/network/teardown.
func (s *Server) handleProvisioningNetworkTeardown(w http.ResponseWriter, r *http.Request) {
	s.queueNetworkTask(w, r, machines.OpNetworkTeardown,
		"Provisioning network teardown task queued")
}
