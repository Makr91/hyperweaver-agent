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

// rdpInfoResponse is GET /machines/{machineName}/rdp's answer: the machine's
// resolvable RDP targets.
type rdpInfoResponse struct {
	MachineName string      `json:"machine_name"`
	Targets     []rdpTarget `json:"targets"`
}

// handleMachineRDPInfo serves GET /machines/{name}/rdp.
//
//	@Summary		RDP connection info
//	@Description	Minimum role: viewer (the host-launchers capability token). The machine's resolvable RDP targets — TWO kinds (Mark's settled design 2026-07-09): `console` = the VRDE hypervisor console at 127.0.0.1:<vrde port> (base VRDP ships in VirtualBox 7.2, NO extpack needed; EFI/boot screens, any guest OS; set the port via settings.consoleport at create or hardware.vrde.port — avoid 3389, it collides with a Windows host's own Remote Desktop; resolves ON the agent host only), and `guest` = a guest's OWN RDP service (Windows guests) at a host-reachable IP — the QEMU guest agent's live view first (the QGA channel, no Guest Additions needed), the Guest Additions' /VirtualBox/GuestInfo/Net/*/V4/IP properties second (the provisioning NAT's 10.0.2.x excluded either way), the document's control IP as fallback, port 3389. NO port-forwards are created; a machine with neither target answers 400 — the capability is honestly absent. rdp_url uses the rdp://full%20address=s:<host>:<port> handler vocabulary.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	rdpInfoResponse	"Resolvable RDP targets"
//	@Failure		400	"Machine not running, or no RDP target resolves (VRDE off and no host-reachable guest IP)"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/rdp [get]
func (s *Server) handleMachineRDPInfo(w http.ResponseWriter, r *http.Request) {
	machine, targets := s.machineRDPTargets(w, r)
	if machine == nil {
		return
	}
	writeJSON(w, rdpInfoResponse{
		MachineName: machine.Name,
		Targets:     targets,
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

// openRDPRequest is POST /machines/{machineName}/open-rdp's optional body.
type openRDPRequest struct {
	// Which resolved target to open (default: console if resolvable, else guest)
	Target string `json:"target"`
}

// openRDPResponse is POST /machines/{machineName}/open-rdp's answer: the target
// the agent host's RDP client was launched at.
type openRDPResponse struct {
	Success     bool       `json:"success"`
	MachineName string     `json:"machine_name"`
	Target      *rdpTarget `json:"target"`
	Message     string     `json:"message"`
}

// handleOpenMachineRDP serves POST /machines/{name}/open-rdp: body optionally
// picks {target: "console" | "guest"}; default = console when VRDE is live,
// else the guest target.
//
//	@Summary		Open an RDP client on the agent host
//	@Description	Minimum role: operator (the host-launchers capability token — the launcher pattern, open-ftp's shape). Launches the AGENT HOST'S RDP client at the chosen target: mstsc /v:<host>:<port> on Windows, the OS rdp:// handler elsewhere (Microsoft Remote Desktop, Remmina). Body optionally picks the target; default = console when VRDE is live, else guest. Direct-mode desktop contract; fire-and-forget.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	openRDPRequest	false	"Optional target selection (console | guest)"
//	@Success		200	{object}	openRDPResponse	"Launch requested"
//	@Failure		400	"Machine not running, requested target unresolvable, or no target at all"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/open-rdp [post]
func (s *Server) handleOpenMachineRDP(w http.ResponseWriter, r *http.Request) {
	machine, targets := s.machineRDPTargets(w, r)
	if machine == nil {
		return
	}
	var body openRDPRequest
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
	writeJSON(w, openRDPResponse{
		Success:     true,
		MachineName: machine.Name,
		Target:      chosen,
		Message:     "RDP client launch requested on the agent host",
	})
}
