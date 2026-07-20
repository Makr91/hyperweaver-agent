package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
)

// The guest-agent surface (Mark's go 2026-07-10, spike-proven the same day):
// /machines/{name}/guest/* speaks the QEMU Guest Agent protocol over the
// machine's COM2→pipe UART — credential-less guest control (live IPs, exec,
// clean shutdown, osinfo) with no SSH and no Guest Additions. The UART is a
// PER-MACHINE create option (zones.guest_agent, default off, under the
// guest_agent.enabled master gate — Mark's Proxmox-model ruling 2026-07-12);
// the setup endpoint opts existing machines in through the modify machinery.

// guestAgentGate answers 503 while guest_agent.enabled is false (the
// file-browser gate's pattern; the guest-agent token disappears with it).
func (s *Server) guestAgentGate(handler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.GuestAgent.Enabled {
			taskError(w, http.StatusServiceUnavailable, "Guest agent channel is disabled")
			return
		}
		handler(w, r)
	})
}

// machineQGAPipe answers a machine's channel address: the working directory
// anchors the Unix socket path; Windows pipes derive from the name alone —
// the same inputs the create wiring used, so they can never disagree.
func (s *Server) machineQGAPipe(machine *machines.Machine) (string, error) {
	workdir := ""
	if machine.Home != nil {
		workdir = *machine.Home
	}
	if workdir == "" {
		machinesDir, err := s.cfg.MachinesDir()
		if err != nil {
			return "", err
		}
		workdir = filepath.Join(machinesDir, provisioner.MachineDirName(machine.Name))
	}
	return qga.PipePath(workdir, machine.Name), nil
}

// guestAgentIP answers the machine's live IPv4 through the guest agent ("" on
// any failure) — the live-truth rung of the RDP/SSH target ladders. utm
// machines answer through utmctl ip-address instead of the QGA UART.
func (s *Server) guestAgentIP(ctx context.Context, machine *machines.Machine) string {
	if machine.Hypervisor == machines.HypervisorUTM {
		exe := machines.UTMCtlPath(ctx)
		if exe == "" {
			return ""
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		ips, err := utm.GuestIPs(probeCtx, exe, machine.VBoxTarget())
		if err != nil {
			return ""
		}
		for _, ip := range ips {
			if machines.UsableGuestIP(ip) {
				return ip
			}
		}
		return ""
	}
	if !s.cfg.GuestAgent.Enabled {
		return ""
	}
	pipe, err := s.machineQGAPipe(machine)
	if err != nil {
		return ""
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := qga.GuestIPv4s(probeCtx, pipe)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

// guestCommand requires the machine running and runs one guest-agent command
// (nil return = response already written).
func (s *Server) guestCommand(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, execute string, arguments any, timeout time.Duration,
) (json.RawMessage, *machines.Machine) {
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return nil, nil
	}
	pipe, err := s.machineQGAPipe(machine)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to resolve the guest-agent channel")
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	result, err := qga.Do(ctx, pipe, execute, arguments)
	if errors.Is(err, qga.ErrNoReply) {
		return nil, machine // the caller decides what silence means
	}
	if err != nil {
		slog.Warn("guest agent command failed", "machine", machine.Name,
			"command", execute, "error", err)
		taskError(w, http.StatusBadGateway,
			"Guest agent did not answer ("+err.Error()+") — the machine needs the guest-agent UART (POST /machines/{name}/guest-agent/setup) and qemu-ga running in the guest")
		return nil, nil
	}
	return result, machine
}

// utmGuestExec runs one command in a utm guest (utmctl exec —
// qemu-guest-agent, synchronous). ok=false means the response is written.
func (s *Server) utmGuestExec(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, timeout time.Duration, command ...string,
) (string, bool) {
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return "", false
	}
	exe := machines.UTMCtlPath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "UTM is not installed")
		return "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	output, err := utm.Exec(ctx, exe, machine.VBoxTarget(), command...)
	if err != nil {
		slog.Warn("utm guest exec failed", "machine", machine.Name, "error", err)
		taskError(w, http.StatusBadGateway,
			"Guest agent did not answer ("+err.Error()+") — the guest needs qemu-guest-agent running")
		return "", false
	}
	return output, true
}

// guestPingResponse is GET /machines/{machineName}/guest/ping's answer.
type guestPingResponse struct {
	Success     bool   `json:"success"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
}

// handleGuestPing serves GET /machines/{name}/guest/ping.
//
//	@Summary		Probe the guest agent
//	@Description	Minimum role: viewer. guest-ping over the machine's QGA channel — the readiness probe (UI gates the guest panel on it per machine). 502 with guidance when the channel or qemu-ga is absent.
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string				true	"Machine name"
//	@Success		200			{object}	guestPingResponse	"Guest agent is responding"
//	@Failure		400			{object}	taskErrorBody		"Machine is not running"
//	@Failure		404			{object}	taskErrorBody		"Machine not found"
//	@Failure		502			{object}	taskErrorBody		"Guest agent did not answer (no UART wired, or qemu-ga not running in the guest)"
//	@Failure		503			{object}	taskErrorBody		"Guest agent channel is disabled (guest_agent.enabled)"
//	@Router			/machines/{machineName}/guest/ping [get]
func (s *Server) handleGuestPing(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		if _, ok := s.utmGuestExec(w, r, machine, 5*time.Second, "whoami"); !ok {
			return
		}
		writeJSON(w, guestPingResponse{
			Success:     true,
			MachineName: machine.Name,
			Message:     "Guest agent is responding",
		})
		return
	}
	_, machine = s.guestCommand(w, r, machine, "guest-ping", nil, 5*time.Second)
	if machine == nil {
		return
	}
	writeJSON(w, guestPingResponse{
		Success:     true,
		MachineName: machine.Name,
		Message:     "Guest agent is responding",
	})
}

// handleGuestOSInfo serves GET /machines/{name}/guest/osinfo — the guest's
// own identity (guest-get-osinfo).
//
//	@Summary		Guest OS identity
//	@Description	Minimum role: viewer. guest-get-osinfo verbatim: {id, name, pretty-name, version, kernel-release, machine, ...} — the guest's OWN self-report.
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string					true	"Machine name"
//	@Success		200			{object}	map[string]interface{}	"OS info"
//	@Failure		400			{object}	taskErrorBody			"Machine is not running"
//	@Failure		404			{object}	taskErrorBody			"Machine not found"
//	@Failure		502			{object}	taskErrorBody			"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody			"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/osinfo [get]
func (s *Server) handleGuestOSInfo(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		taskError(w, http.StatusBadRequest, "osinfo is not supported on utm machines (no utmctl verb)")
		return
	}
	result, machine := s.guestCommand(w, r, machine, "guest-get-osinfo", nil, 5*time.Second)
	if machine == nil {
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"osinfo":       result,
	})
}

// handleGuestNetwork serves GET /machines/{name}/guest/network — the guest's
// live interfaces (guest-network-get-interfaces): real addresses with no
// Guest Additions. utm answers a flat ips[] — utmctl ip-address reports bare
// addresses, never the QGA interface shape.
//
//	@Summary		Guest live network interfaces
//	@Description	Minimum role: viewer. guest-network-get-interfaces verbatim: per-interface name, hardware-address, and live ip-addresses — REAL guest addressing with no Guest Additions (the same data feeding the RDP/SSH target ladders). utm machines answer a FLAT ips[] list instead of interfaces[] (utmctl ip-address exposes addresses only).
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string					true	"Machine name"
//	@Success		200			{object}	map[string]interface{}	"Interfaces"
//	@Failure		400			{object}	taskErrorBody			"Machine is not running"
//	@Failure		404			{object}	taskErrorBody			"Machine not found"
//	@Failure		502			{object}	taskErrorBody			"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody			"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/network [get]
func (s *Server) handleGuestNetwork(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
			taskError(w, http.StatusBadRequest, "Machine is not running")
			return
		}
		exe := machines.UTMCtlPath(r.Context())
		if exe == "" {
			taskError(w, http.StatusServiceUnavailable, "UTM is not installed")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		ips, err := utm.GuestIPs(ctx, exe, machine.VBoxTarget())
		if err != nil {
			slog.Warn("utm guest ip-address failed", "machine", machine.Name, "error", err)
			taskError(w, http.StatusBadGateway,
				"Guest agent did not answer ("+err.Error()+") — the guest needs qemu-guest-agent running")
			return
		}
		writeJSON(w, map[string]any{
			"machine_name": machine.Name,
			"ips":          ips,
		})
		return
	}
	result, machine := s.guestCommand(w, r, machine, "guest-network-get-interfaces", nil, 5*time.Second)
	if machine == nil {
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"interfaces":   result,
	})
}

// guestShutdownRequest is POST /machines/{machineName}/guest/shutdown's body.
type guestShutdownRequest struct {
	// powerdown (default), reboot, or halt
	Mode string `json:"mode"`
}

// guestShutdownResponse is POST /machines/{machineName}/guest/shutdown's answer.
type guestShutdownResponse struct {
	Success     bool   `json:"success"`
	MachineName string `json:"machine_name"`
	Mode        string `json:"mode"`
	Message     string `json:"message"`
}

// handleGuestShutdown serves POST /machines/{name}/guest/shutdown — a CLEAN
// in-guest shutdown/reboot/halt (guest-shutdown). The guest may power off
// before replying, so silence after delivery is success.
//
//	@Summary		Clean in-guest shutdown
//	@Description	Minimum role: operator. guest-shutdown {mode: powerdown (default) | reboot | halt} — the guest's OWN orderly shutdown, cleaner than ACPI guessing. The guest may power off before replying; silence after delivery counts as success. The registry catches the resulting state change on its normal refresh — this is the GUEST acting, not a queued agent task.
//	@Tags			Guest Agent
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path		string					true	"Machine name"
//	@Param			request		body		guestShutdownRequest	false	"Shutdown mode"
//	@Success		200			{object}	guestShutdownResponse	"Shutdown requested through the guest agent"
//	@Failure		400			{object}	taskErrorBody			"Invalid mode, or machine is not running"
//	@Failure		404			{object}	taskErrorBody			"Machine not found"
//	@Failure		502			{object}	taskErrorBody			"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody			"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/shutdown [post]
func (s *Server) handleGuestShutdown(w http.ResponseWriter, r *http.Request) {
	mode := "powerdown"
	if r.ContentLength > 0 {
		var body guestShutdownRequest
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		switch body.Mode {
		case "", "powerdown":
		case "reboot", "halt":
			mode = body.Mode
		default:
			taskError(w, http.StatusBadRequest, "mode must be powerdown, reboot, or halt")
			return
		}
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		if mode != "powerdown" {
			taskError(w, http.StatusBadRequest,
				"guest "+mode+" is not supported on utm machines — only powerdown (rides utmctl stop)")
			return
		}
		if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
			taskError(w, http.StatusBadRequest, "Machine is not running")
			return
		}
		exe := machines.UTMCtlPath(r.Context())
		if exe == "" {
			taskError(w, http.StatusServiceUnavailable, "UTM is not installed")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if serr := utm.Stop(ctx, exe, machine.VBoxTarget(), false); serr != nil {
			slog.Warn("utm guest shutdown failed", "machine", machine.Name, "error", serr)
			taskError(w, http.StatusBadGateway, "Guest shutdown did not take ("+serr.Error()+")")
			return
		}
		slog.Info("guest shutdown requested", "machine", machine.Name, "mode", mode,
			"by", auth.FromContext(r.Context()).Name)
		writeJSON(w, guestShutdownResponse{
			Success:     true,
			MachineName: machine.Name,
			Mode:        mode,
			Message:     "Guest powerdown requested — rides utmctl stop (graceful)",
		})
		return
	}
	_, machine = s.guestCommand(w, r, machine, "guest-shutdown", map[string]any{"mode": mode}, 5*time.Second)
	if machine == nil {
		return
	}
	slog.Info("guest shutdown requested", "machine", machine.Name, "mode", mode,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, guestShutdownResponse{
		Success:     true,
		MachineName: machine.Name,
		Mode:        mode,
		Message:     "Guest " + mode + " requested through the guest agent",
	})
}
