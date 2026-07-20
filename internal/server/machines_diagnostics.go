package server

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// injectNMIResponse is POST /machines/{machineName}/nmi's synchronous answer.
type injectNMIResponse struct {
	Success     bool   `json:"success"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
}

// handleInjectNMI serves POST /machines/{machineName}/nmi — inject a
// non-maskable interrupt into the running machine (VBoxManage debugvm
// injectnmi): the diagnostic trigger for guest crash dumps / kernel
// debuggers, zoneweaver's bhyvectl --inject-nmi mirror (Mark's parity go
// 2026-07-12). Synchronous like the base's — the injection is instantaneous,
// no task row.
//
//	@Summary		Inject an NMI into a running machine
//	@Description	Minimum role: operator. VBoxManage debugvm injectnmi — a non-maskable interrupt into the running guest: the diagnostic trigger for guest crash dumps and kernel debuggers (zoneweaver's bhyvectl --inject-nmi, same wire on both agents). SYNCHRONOUS — the injection is instantaneous, no task row. What happens next is the guest's own policy (Windows: crash dump when configured; Linux: kernel NMI handler/panic per sysctl).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	injectNMIResponse	"NMI injected"
//	@Failure		400	"Machine is not running"
//	@Failure		404	"Machine not found"
//	@Failure		500	"VBoxManage debugvm failed"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/nmi [post]
func (s *Server) handleInjectNMI(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Can only inject an NMI into a running machine")
		return
	}
	if err := vbox.InjectNMI(r.Context(), exe, machine.VBoxTarget()); err != nil {
		slog.Error("inject nmi", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to inject NMI")
		return
	}
	slog.Info("nmi injected", "machine", machine.Name,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, injectNMIResponse{
		Success:     true,
		MachineName: machine.Name,
		Message:     "NMI injected",
	})
}

// handleMachineScreenshot serves a PNG of the running machine's framebuffer
// (`controlvm screenshotpng`) — the base's no-session screenshot endpoint;
// synchronous, no console session needed.
//
//	@Summary		Console screenshot
//	@Description	Minimum role: viewer (the machine-screenshot capability token). Synchronous PNG capture of the running machine's framebuffer (VBoxManage controlvm screenshotpng) — no console session or extpack needed.
//	@Tags			Console
//	@Produce		png
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{file}	binary	"PNG screenshot"
//	@Failure		404	"Machine not found"
//	@Failure		502	"Machine not running, or capture failed"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/vnc/screenshot [get]
func (s *Server) handleMachineScreenshot(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadGateway, "Machine is not running — no framebuffer to capture")
		return
	}

	// A temp DIRECTORY, not a pre-created file: VBoxManage itself writes the
	// PNG — the agent never opens a write handle here (one write path rule).
	dir, err := os.MkdirTemp("", "hw-screenshot-")
	if err != nil {
		slog.Error("screenshot temp dir", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to capture screenshot")
		return
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()
	path := filepath.Join(dir, "screen.png")

	if serr := vbox.Screenshot(r.Context(), exe, machine.VBoxTarget(), path); serr != nil {
		slog.Error("screenshot capture", "machine", machine.Name, "error", serr)
		taskError(w, http.StatusBadGateway, "Failed to capture screenshot")
		return
	}
	png, err := os.ReadFile(filepath.Clean(path))
	if err != nil || len(png) == 0 {
		taskError(w, http.StatusBadGateway, "Failed to capture screenshot")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if _, werr := w.Write(png); werr != nil {
		slog.Error("write screenshot response", "error", werr)
	}
}

// handleGuestProperties serves the machine's full guest-property set
// (VBoxManage guestproperty enumerate) — the post-boot view: guest-additions
// IPs, OS info, and this agent's cloud-init keys. Read-only, synchronous.
//
//	@Summary		Enumerate guest properties
//	@Description	Minimum role: viewer. Synchronous VBoxManage guestproperty enumerate — the post-boot view: guest-additions data (/VirtualBox/GuestInfo/Net/* carries the guest's live IPs), OS info, and this agent's cloud-init keys.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"Guest properties"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/guest-properties [get]
func (s *Server) handleGuestProperties(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	entries, err := vbox.EnumerateGuestProperties(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("enumerate guest properties", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to enumerate guest properties")
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"properties":   entries,
		"total":        len(entries),
	})
}
