package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/openbrowser"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The RDP launcher — Mark's settled design (2026-07-09): open-ftp's launcher
// pattern with TWO targets. (a) The VRDE console at localhost:<vrde port> —
// base VRDP ships in VirtualBox 7.2 (no extpack; proven live on Mark's host,
// mstsc-tested): the HYPERVISOR console incl. EFI/boot screens, any guest OS.
// (b) A guest's OWN RDP service at a host-reachable IP — Guest Additions live
// IPs (NAT 10.0.2.x excluded), the document's control IP as fallback. NO new
// port-forward plumbing; no resolvable target = 400, the capability is
// honestly absent. POST launches on the AGENT host (Direct-mode desktop
// contract); GET serves the info document for a remote UI's own handoff —
// note a console target (127.0.0.1) only resolves ON the agent host.

// rdpTarget is one reachable RDP endpoint.
type rdpTarget struct {
	Type        string `json:"type"` // console | guest
	Host        string `json:"host"`
	Port        int    `json:"port"`
	RDPURL      string `json:"rdp_url"`
	Description string `json:"description"`
}

// guestRDPAddress resolves a host-reachable guest IP: the guest agent's live
// view first (the QGA channel — works with no Guest Additions at all), the
// Guest Additions' properties second, the document's control IP as fallback
// ("" when none). The filter and property pattern are the machines package's
// — one definition shared with the discovery sweep's stored guest_info.
func (s *Server) guestRDPAddress(ctx context.Context, vboxExe string, machine *machines.Machine,
	config machines.MachineConfig,
) string {
	if ip := s.guestAgentIP(ctx, machine); machines.UsableGuestIP(ip) {
		return ip
	}
	if entries, err := vbox.EnumerateGuestProperties(ctx, vboxExe, machine.VBoxTarget()); err == nil {
		for _, entry := range entries {
			if machines.GuestPropertyIPName.MatchString(entry.Name) && machines.UsableGuestIP(entry.Value) {
				return entry.Value
			}
		}
	}
	if ip := machines.ExtractControlIP(config.List("networks")); machines.UsableGuestIP(ip) {
		return ip
	}
	return ""
}

// rdpURL renders the rdp:// form OS handlers register (Microsoft Remote
// Desktop's full-address parameter vocabulary).
func rdpURL(host string, port int) string {
	return "rdp://full%20address=s:" + net.JoinHostPort(host, strconv.Itoa(port))
}

// machineRDPTargets resolves a machine's RDP targets, writing the error
// answer itself when none resolve (nil return = response already written).
func (s *Server) machineRDPTargets(w http.ResponseWriter, r *http.Request) (*machines.Machine, []rdpTarget) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return nil, nil
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return nil, nil
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return nil, nil
	}
	if err != nil {
		slog.Error("rdp target probe", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to read machine state")
		return nil, nil
	}
	if machines.MapVBoxState(info.State) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return nil, nil
	}

	targets := []rdpTarget{}
	if enabled, port := vrdePort(info); enabled && port > 0 {
		targets = append(targets, rdpTarget{
			Type: "console", Host: "127.0.0.1", Port: port,
			RDPURL:      rdpURL("127.0.0.1", port),
			Description: "VRDE hypervisor console (EFI/boot screens, any guest OS) — resolves on the agent host only",
		})
	}
	config := machines.ParseConfiguration(machine)
	if ip := s.guestRDPAddress(r.Context(), exe, machine, config); ip != "" {
		targets = append(targets, rdpTarget{
			Type: "guest", Host: ip, Port: 3389,
			RDPURL:      rdpURL(ip, 3389),
			Description: "The guest's own RDP service (Windows guests) at its host-reachable IP",
		})
	}
	if len(targets) == 0 {
		taskError(w, http.StatusBadRequest,
			"No RDP target: VRDE is off (enable it via modify {vnc: \"on\"} or hardware.vrde) and no host-reachable guest IP is known (Guest Additions report none; no control IP in networks[])")
		return nil, nil
	}
	return machine, targets
}

// handleMachineRDPInfo serves GET /machines/{name}/rdp.
func (s *Server) handleMachineRDPInfo(w http.ResponseWriter, r *http.Request) {
	machine, targets := s.machineRDPTargets(w, r)
	if machine == nil {
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"targets":      targets,
	})
}

// launchRDP hands one target to the agent host's RDP client: mstsc directly
// on Windows (no rdp:// handler exists there), the OS rdp:// handler
// elsewhere (Microsoft Remote Desktop on macOS, Remmina and friends on
// Linux). Fire-and-forget like every launcher.
func launchRDP(target *rdpTarget) {
	if runtime.GOOS != "windows" {
		openbrowser.Open(target.RDPURL, "")
		return
	}
	// mstsc ships with Windows and lives on the system PATH.
	cmd := exec.CommandContext(context.Background(), "mstsc",
		"/v:"+net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	cmd.SysProcAttr = procattr.NoConsole()
	if err := cmd.Start(); err != nil {
		slog.Error("launch mstsc", "target", target.Host, "error", err)
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Warn("mstsc exited with error", "error", err)
		}
	}()
}

// handleOpenMachineRDP serves POST /machines/{name}/open-rdp: body optionally
// picks {target: "console" | "guest"}; default = console when VRDE is live,
// else the guest target.
func (s *Server) handleOpenMachineRDP(w http.ResponseWriter, r *http.Request) {
	machine, targets := s.machineRDPTargets(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Target string `json:"target"`
	}
	if r.ContentLength > 0 {
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
	}
	var chosen *rdpTarget
	if body.Target != "" {
		for i := range targets {
			if targets[i].Type == body.Target {
				chosen = &targets[i]
				break
			}
		}
		if chosen == nil {
			taskError(w, http.StatusBadRequest,
				"Requested RDP target "+body.Target+" is not resolvable on this machine")
			return
		}
	} else {
		chosen = &targets[0]
	}

	launchRDP(chosen)
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"target":       chosen,
		"message":      "RDP client launch requested on the agent host",
	})
}
