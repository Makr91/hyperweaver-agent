package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The VNC console slice — the base's websockify proxy on this hypervisor's
// terms: VirtualBox's VRDE server IS the machine's remote display (no
// separate session process to manage — the base's session lifecycle collapses
// into the VM itself). With the VNC extpack (VRDE Module VBoxVNC) the VRDE
// port speaks RFB, and /machines/{name}/vnc/websockify bridges a noVNC
// browser client onto it (WebSocket ↔ TCP). GET /machines/{name}/vnc reports
// the live console state the UI needs before connecting.

// vncCapability caches the extpack probe (extpack installs are rare; a probe
// per /status poll would shell out constantly). Restart the agent after
// installing the VNC extpack.
var (
	vncCapabilityOnce sync.Once
	vncCapable        bool
)

// vncConsoleAvailable reports whether a usable VNC-speaking VRDE module is
// installed.
func vncConsoleAvailable(ctx context.Context) bool {
	vncCapabilityOnce.Do(func() {
		exe := machines.VBoxManagePath(ctx)
		if exe == "" {
			return
		}
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		vncCapable = vbox.VNCExtpackUsable(probeCtx, exe)
	})
	return vncCapable
}

// vrdePort reads the machine's live VRDE state from the machinereadable view:
// enabled + the bound port ("vrdeport" while running; the configured
// "vrdeports" value otherwise).
func vrdePort(info *vbox.Info) (enabled bool, port int) {
	if info.Raw["vrde"] != "on" {
		return false, 0
	}
	if raw, ok := info.Raw["vrdeport"]; ok {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return true, n
		}
	}
	if raw, ok := info.Raw["vrdeports"]; ok {
		// A configured range ("5940" or "5940-5949") — the first value is
		// where a single-VM server binds.
		for i := 0; i < len(raw); i++ {
			if raw[i] < '0' || raw[i] > '9' {
				raw = raw[:i]
				break
			}
		}
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			return true, n
		}
	}
	return true, 0
}

// vncStateResponse is GET /machines/{name}/vnc's answer — the machine's live
// VRDE console state the UI reads before connecting.
type vncStateResponse struct {
	MachineName string `json:"machine_name"`
	VRDEEnabled bool   `json:"vrde_enabled"`
	VRDEPort    int    `json:"vrde_port"`
	VNCCapable  bool   `json:"vnc_capable"`
	Running     bool   `json:"running"`
	// Console-details facts (the UI AI's third ask, 2026-07-10): the guest
	// display's WxHxD (empty when unknown) and the Guest Additions run level
	// (0 none, 1 system, 2 userland, 3 desktop).
	VideoMode         string `json:"video_mode"`
	AdditionsRunLevel int    `json:"additions_run_level"`
	WebSocketURL      string `json:"websocket_url"`
}

// handleVncInfo serves GET /machines/{name}/vnc: the live console state
// (VRDE on/off, port, whether the host can actually speak VNC on it).
//
//	@Summary		VNC console state
//	@Description	Minimum role: viewer. The machine's live VRDE console state — everything the UI needs before connecting: whether VRDE is on and its port, whether the host can actually speak VNC on it (vnc_capable: a usable VBoxVNC extpack module; without it the VRDE port speaks RDP, which noVNC cannot), the websockify URL, plus the console-details facts (the UI AI's third ask, 2026-07-10): video_mode (the guest display's WxHxD, e.g. 1024x768x32; empty when unknown) and additions_run_level (0 = no Guest Additions running, 1 = system, 2 = userland, 3 = desktop).
//	@Tags			Console
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	vncStateResponse	"Console state"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/vnc [get]
func (s *Server) handleVncInfo(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
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
		slog.Error("vnc info", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to read console state")
		return
	}
	enabled, port := vrdePort(info)
	writeJSON(w, vncStateResponse{
		MachineName: machine.Name,
		VRDEEnabled: enabled,
		VRDEPort:    port,
		VNCCapable:  vncConsoleAvailable(r.Context()),
		Running:     machines.MapVBoxState(info.State) == machines.StatusRunning,
		// Console-details facts (the UI AI's third ask, 2026-07-10).
		VideoMode:         videoMode(info),
		AdditionsRunLevel: additionsRunLevel(info),
		WebSocketURL:      "/machines/" + machine.Name + "/vnc/websockify",
	})
}

// videoMode renders the machinereadable VideoMode value ("1024,768,32"@0,0 1
// — width,height,depth plus origin/monitor) as the familiar WxHxD string
// ("" when unknown).
func videoMode(info *vbox.Info) string {
	raw, ok := info.Raw["VideoMode"]
	if !ok {
		return ""
	}
	if at := strings.IndexByte(raw, '@'); at >= 0 {
		raw = raw[:at]
	}
	return strings.ReplaceAll(strings.Trim(raw, `"`), ",", "x")
}

// additionsRunLevel reads the Guest Additions run level (0 = none/not
// running, 1 = system, 2 = userland, 3 = desktop).
func additionsRunLevel(info *vbox.Info) int {
	if raw, ok := info.Raw["GuestAdditionsRunLevel"]; ok {
		if n, err := strconv.Atoi(raw); err == nil {
			return n
		}
	}
	return 0
}

// handleVncWebsockify bridges the browser's WebSocket onto the machine's
// VRDE port (the base's websockify proxy): binary frames ↔ raw TCP, closed
// when either side ends.
func (s *Server) handleVncWebsockify(w http.ResponseWriter, r *http.Request) {
	if !s.requireTicket(w, r) {
		return
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if err != nil {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if machines.MapVBoxState(info.State) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return
	}
	enabled, port := vrdePort(info)
	if !enabled || port <= 0 {
		taskError(w, http.StatusBadRequest,
			"Machine has no active VRDE console (enable it: settings.consoleport at create, or vnc via modify)")
		return
	}

	dialer := net.Dialer{Timeout: 10 * time.Second}
	backend, err := dialer.DialContext(r.Context(), "tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		slog.Warn("vnc backend dial failed", "machine", machine.Name, "port", port, "error", err)
		taskError(w, http.StatusBadGateway, "Console server connection failed")
		return
	}
	defer func() {
		_ = backend.Close()
	}()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
		// noVNC negotiates the "binary" subprotocol.
		Subprotocols: []string{"binary"},
	})
	if err != nil {
		slog.Warn("vnc websockify accept failed", "machine", machine.Name, "error", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// WS → TCP.
	go func() {
		defer cancel()
		for {
			_, data, rerr := conn.Read(ctx)
			if rerr != nil {
				return
			}
			if _, werr := backend.Write(data); werr != nil {
				return
			}
		}
	}()

	// TCP → WS (this goroutine owns the writes — one writer per direction).
	buffer := make([]byte, 32*1024)
	for {
		length, rerr := backend.Read(buffer)
		if length > 0 {
			writeCtx, done := context.WithTimeout(ctx, 30*time.Second)
			werr := conn.Write(writeCtx, websocket.MessageBinary, buffer[:length])
			done()
			if werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
