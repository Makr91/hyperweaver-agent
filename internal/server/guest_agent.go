package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
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

// guestExecStatus is guest-exec-status' answer with the base64 output fields
// decoded for the wire.
type guestExecStatus struct {
	Exited   bool   `json:"exited"`
	ExitCode *int   `json:"exitcode,omitempty"`
	Signal   *int   `json:"signal,omitempty"`
	OutData  string `json:"out-data,omitempty"`
	ErrData  string `json:"err-data,omitempty"`
}

// decodeExecStatus parses guest-exec-status and decodes its base64 halves.
func decodeExecStatus(raw json.RawMessage) (map[string]any, error) {
	var status guestExecStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	result := map[string]any{"exited": status.Exited}
	if status.ExitCode != nil {
		result["exitcode"] = *status.ExitCode
	}
	if status.Signal != nil {
		result["signal"] = *status.Signal
	}
	if status.OutData != "" {
		if decoded, err := base64.StdEncoding.DecodeString(status.OutData); err == nil {
			result["stdout"] = string(decoded)
		}
	}
	if status.ErrData != "" {
		if decoded, err := base64.StdEncoding.DecodeString(status.ErrData); err == nil {
			result["stderr"] = string(decoded)
		}
	}
	return result, nil
}

// guestExecRequest is POST /machines/{machineName}/guest/exec's body.
type guestExecRequest struct {
	// The guest executable (absolute path; no shell)
	Path string `json:"path"`
	// Arguments passed to the executable
	Args []string `json:"args"`
	// Poll to completion (default true); false answers the pid immediately
	Wait *bool `json:"wait"`
	// Poll budget in seconds (default 30, max 600)
	TimeoutSeconds int `json:"timeout_seconds"`
}

// handleGuestExec serves POST /machines/{name}/guest/exec: run a command in
// the guest (guest-exec). wait (default true) polls guest-exec-status until
// exit or timeout_seconds (default 30, max 600); wait:false answers the pid
// for GET /machines/{name}/guest/exec/{pid}.
//
//	@Summary		Run a command in the guest
//	@Description	Minimum role: operator. guest-exec with capture-output: path is the guest executable (absolute; no shell — wrap in /bin/sh -c or cmd.exe /c yourself for shell syntax), args[] its arguments. wait (default true) polls guest-exec-status until exit or timeout_seconds (default 30, max 600) and answers {exitcode, stdout, stderr} (base64 decoded); wait:false answers {pid} immediately for GET /machines/{name}/guest/exec/{pid}. Credential-less by design — the channel itself is the authority (operator role + the machine's own host).
//	@Tags			Guest Agent
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path		string				true	"Machine name"
//	@Param			request		body		guestExecRequest	true	"Command to run in the guest"
//	@Success		200			{object}	map[string]interface{}	"Exit status with decoded output (wait), the pid (wait:false), or a still-running notice past the timeout"
//	@Failure		400			{object}	taskErrorBody		"Missing path, or machine is not running"
//	@Failure		404			{object}	taskErrorBody		"Machine not found"
//	@Failure		502			{object}	taskErrorBody		"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody		"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/exec [post]
func (s *Server) handleGuestExec(w http.ResponseWriter, r *http.Request) {
	var body guestExecRequest
	if err := decodeBody(r, &body); err != nil || body.Path == "" {
		taskError(w, http.StatusBadRequest, "Body needs path (the guest executable) and optional args[]")
		return
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		if body.Wait != nil && !*body.Wait {
			taskError(w, http.StatusBadRequest,
				"utmctl exec is synchronous — wait:false is not supported on utm machines")
			return
		}
		timeout := body.TimeoutSeconds
		if timeout <= 0 {
			timeout = 30
		}
		if timeout > 600 {
			timeout = 600
		}
		output, ok := s.utmGuestExec(w, r, machine, time.Duration(timeout)*time.Second,
			append([]string{body.Path}, body.Args...)...)
		if !ok {
			return
		}
		slog.Info("guest exec", "machine", machine.Name, "path", body.Path,
			"by", auth.FromContext(r.Context()).Name)
		writeJSON(w, map[string]any{
			"success":      true,
			"machine_name": machine.Name,
			"exited":       true,
			"stdout":       output,
		})
		return
	}
	result, machine := s.guestCommand(w, r, machine, "guest-exec", map[string]any{
		"path":           body.Path,
		"arg":            body.Args,
		"capture-output": true,
	}, 10*time.Second)
	if machine == nil {
		return
	}
	var started struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(result, &started); err != nil {
		taskError(w, http.StatusBadGateway, "Guest agent answered an unexpected exec shape")
		return
	}
	slog.Info("guest exec", "machine", machine.Name, "path", body.Path,
		"pid", started.PID, "by", auth.FromContext(r.Context()).Name)

	if body.Wait != nil && !*body.Wait {
		writeJSON(w, map[string]any{
			"success":      true,
			"machine_name": machine.Name,
			"pid":          started.PID,
			"message":      "Command started — poll GET /machines/{name}/guest/exec/" + strconv.Itoa(started.PID),
		})
		return
	}

	timeout := body.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	if timeout > 600 {
		timeout = 600
	}
	pipe, perr := s.machineQGAPipe(machine)
	if perr != nil {
		taskError(w, http.StatusInternalServerError, "Failed to resolve the guest-agent channel")
		return
	}
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		pollCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		raw, err := qga.Do(pollCtx, pipe, "guest-exec-status", map[string]any{"pid": started.PID})
		cancel()
		if err != nil {
			taskError(w, http.StatusBadGateway, "Guest agent stopped answering while waiting: "+err.Error())
			return
		}
		status, derr := decodeExecStatus(raw)
		if derr != nil {
			taskError(w, http.StatusBadGateway, "Guest agent answered an unexpected status shape")
			return
		}
		if exited, _ := status["exited"].(bool); exited {
			status["success"] = true
			status["machine_name"] = machine.Name
			status["pid"] = started.PID
			writeJSON(w, status)
			return
		}
		if time.Now().After(deadline) {
			writeJSON(w, map[string]any{
				"success":      true,
				"machine_name": machine.Name,
				"pid":          started.PID,
				"exited":       false,
				"message":      "Still running after " + strconv.Itoa(timeout) + "s — poll GET /machines/{name}/guest/exec/" + strconv.Itoa(started.PID),
			})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// handleGuestExecStatus serves GET /machines/{name}/guest/exec/{pid}.
//
//	@Summary		Poll a guest command
//	@Description	Minimum role: viewer. guest-exec-status for a pid from POST /guest/exec: {exited, exitcode?, stdout?, stderr?} — output arrives once the process exits.
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string					true	"Machine name"
//	@Param			pid			path		int						true	"Guest process id"
//	@Success		200			{object}	map[string]interface{}	"Process status"
//	@Failure		400			{object}	taskErrorBody			"Invalid pid, or machine is not running"
//	@Failure		404			{object}	taskErrorBody			"Machine not found"
//	@Failure		502			{object}	taskErrorBody			"Guest agent did not answer"
//	@Failure		503			{object}	taskErrorBody			"Guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest/exec/{pid} [get]
func (s *Server) handleGuestExecStatus(w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(r.PathValue("pid"))
	if err != nil || pid <= 0 {
		taskError(w, http.StatusBadRequest, "Invalid pid")
		return
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		taskError(w, http.StatusBadRequest, "not supported on utm machines (utmctl exec is synchronous)")
		return
	}
	result, machine := s.guestCommand(w, r, machine, "guest-exec-status", map[string]any{"pid": pid}, 5*time.Second)
	if machine == nil {
		return
	}
	status, derr := decodeExecStatus(result)
	if derr != nil {
		taskError(w, http.StatusBadGateway, "Guest agent answered an unexpected status shape")
		return
	}
	status["machine_name"] = machine.Name
	status["pid"] = pid
	writeJSON(w, status)
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

// handleGuestAgentSetup serves POST /machines/{machineName}/guest-agent/setup
// — opt an existing machine into the guest-agent UART (creates wire it only
// when the spec says zones.guest_agent: true): the COM2→pipe serial config
// rides the ordinary modify machinery, queued against a powered-off machine,
// accrued for the next power cycle otherwise (the vrde-tls pattern).
//
//	@Summary		Wire the guest-agent UART onto an existing machine
//	@Description	Minimum role: operator. Machines created with vbox.guest_agent: true get the UART at build — this opts in everything else (existing machines, discovered VMs, creates that omitted the flag): vbox.serial port 2 (0x2F8/IRQ3, uart-mode server onto the machine's deterministic pipe) rides the ordinary modify machinery — a machine_modify task against a powered-off machine, the accrue-changes contract (pending_power_cycle) otherwise. The GUEST half must run qemu-ga on its COM2 (current box templates bake the auto-transport config in; older guests need it added). A document that claims serial port 2 itself is never overridden at create; this endpoint is the explicit override.
//	@Tags			Guest Agent
//	@Produce		json
//	@Param			machineName	path		string						true	"Machine name"
//	@Success		200			{object}	map[string]interface{}		"Setup queued (powered off) or accrued (pending_power_cycle)"
//	@Failure		404			{object}	taskErrorBody				"Machine not found, or no VM exists behind it yet"
//	@Failure		503			{object}	taskErrorBody				"VirtualBox is not installed, or the guest agent channel is disabled"
//	@Router			/machines/{machineName}/guest-agent/setup [post]
func (s *Server) handleGuestAgentSetup(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Hypervisor == machines.HypervisorUTM {
		taskError(w, http.StatusBadRequest,
			"the guest-agent UART is VirtualBox plumbing — utm guests use qemu-guest-agent via utmctl already")
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("guest-agent setup probe", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to read machine state")
		return
	}
	pipe, err := s.machineQGAPipe(machine)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to resolve the guest-agent channel")
		return
	}

	doc := map[string]any{
		"vbox": map[string]any{
			"serial": []any{map[string]any{
				"port":    2,
				"io_base": "0x2F8",
				"irq":     3,
				"mode":    "server " + pipe,
			}},
		},
	}
	switch machines.MapVBoxState(info.State) {
	case machines.StatusStopped, machines.StatusAborted:
		metadata, merr := json.Marshal(doc)
		if merr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to queue the guest-agent setup")
			return
		}
		metadataStr := string(metadata)
		task, terr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: machine.Name,
			Operation:   machines.OpModify,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
			Metadata:    &metadataStr,
		})
		if terr != nil {
			slog.Error("queue guest-agent setup", "machine", machine.Name, "error", terr)
			taskError(w, http.StatusInternalServerError, "Failed to queue the guest-agent setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"task_id":          task.ID,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           tasks.StatusPending,
			"requires_restart": true,
			"pipe":             pipe,
			"message":          "Guest-agent UART setup queued (machine is powered off) — the guest needs qemu-ga on its COM2 (baked into current box templates).",
		})
	default:
		merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, doc)
		if merr != nil {
			slog.Error("accrue guest-agent setup", "machine", machine.Name, "error", merr)
			taskError(w, http.StatusInternalServerError, "Failed to store the guest-agent setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           "pending_power_cycle",
			"requires_restart": true,
			"pending_changes":  merged,
			"pipe":             pipe,
			"message":          "Guest-agent UART setup accrued — applies at the next agent-driven power cycle; the guest needs qemu-ga on its COM2 (baked into current box templates).",
		})
	}
}
