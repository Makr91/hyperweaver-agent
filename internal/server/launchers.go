package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/openbrowser"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Machine launchers — the per-machine "Open Directory" / "Open FTP Client"
// buttons (Mark's ruling 2026-07-07: BOTH ways ship). The POST endpoints
// launch on the AGENT host — the Direct-mode desktop contract, where the
// browser and the agent share the machine (elsewhere they harmlessly open a
// window on the agent's own desktop). The GET info endpoint returns the sftp
// URL so a remote UI can instead hand it to the USER'S own OS handler
// (window.open) — the general answer when the browser is not the agent host.
// PLUS the external-applications registry (Mark's go 2026-07-12, superseding
// the earlier not-blessed note): config applications[] entries — user-chosen
// tools like PuTTY/WinSCP with argument templates — launched per machine
// with {host}/{port}/{user}/{password}/{machine} resolved through the SSH
// transport ladder and stored credentials.

// ftpInfo is the GET /machines/{name}/ftp answer: the SFTP target built from
// the stored credentials and the pipeline's transport ladder (NAT ssh
// port-forward first, control IP fallback — the ssh-terminal's exact rules).
type ftpInfo struct {
	MachineName string `json:"machine_name"`
	SFTPURL     string `json:"sftp_url"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
}

// machineFTPInfo resolves a machine's SFTP target, writing the error answer
// itself when the machine cannot serve one (mirrors handleStartSSHSession's
// preconditions — same transport, same credentials).
func (s *Server) machineFTPInfo(w http.ResponseWriter, r *http.Request) *ftpInfo {
	machine := s.findMachine(w, r)
	if machine == nil {
		return nil
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return nil
	}
	machineConfig := machines.ParseConfiguration(machine)
	credentials := machines.ExtractCredentials(machineConfig.Section("settings"))
	if credentials.Username == "" {
		taskError(w, http.StatusBadRequest,
			"SSH credentials not configured. Set settings.vagrant_user in the machine configuration.")
		return nil
	}
	host, port := s.sshTransport(r.Context(), machine, machineConfig)
	if host == "" {
		taskError(w, http.StatusBadRequest,
			"No SSH transport: machine has no NAT ssh port-forward, no guest-agent-reported IP, and no control IP in networks[] (set is_control: true on one network)")
		return nil
	}
	target := url.URL{
		Scheme: "sftp",
		User:   url.User(credentials.Username),
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/",
	}
	return &ftpInfo{
		MachineName: machine.Name,
		SFTPURL:     target.String(),
		Host:        host,
		Port:        port,
		Username:    credentials.Username,
	}
}

// handleMachineFTPInfo serves GET /machines/{name}/ftp.
func (s *Server) handleMachineFTPInfo(w http.ResponseWriter, r *http.Request) {
	info := s.machineFTPInfo(w, r)
	if info == nil {
		return
	}
	writeJSON(w, info)
}

// handleOpenMachineFTP serves POST /machines/{name}/open-ftp: hands the sftp
// URL to the agent host's default handler (FileZilla and friends register
// sftp://). Fire-and-forget like the tray's browser open — a missing handler
// surfaces on the host's own desktop, not here.
func (s *Server) handleOpenMachineFTP(w http.ResponseWriter, r *http.Request) {
	info := s.machineFTPInfo(w, r)
	if info == nil {
		return
	}
	openbrowser.Open(info.SFTPURL, "")
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": info.MachineName,
		"sftp_url":     info.SFTPURL,
		"message":      "SFTP client launch requested on the agent host",
	})
}

// applicationInfo is one GET /applications entry: the configured tool plus
// whether its executable actually exists on this host (SHI's ApplicationData
// .exists — a launch against a missing binary is refused, never spawned).
type applicationInfo struct {
	Name   string   `json:"name"`
	Path   string   `json:"path"`
	Args   []string `json:"args"`
	Exists bool     `json:"exists"`
}

// handleListApplications serves GET /applications — the configured external
// applications (config applications[]) with a live existence check, feeding
// the UI's per-machine launch menu and its applications settings page.
func (s *Server) handleListApplications(w http.ResponseWriter, _ *http.Request) {
	list := make([]applicationInfo, 0, len(s.cfg.Applications))
	for i := range s.cfg.Applications {
		entry := &s.cfg.Applications[i]
		stat, err := os.Stat(entry.Path)
		list = append(list, applicationInfo{
			Name:   entry.Name,
			Path:   entry.Path,
			Args:   entry.Args,
			Exists: err == nil && !stat.IsDir(),
		})
	}
	writeJSON(w, map[string]any{"applications": list, "total": len(list)})
}

// findApplication answers the configured application with this name (nil when
// none) — names are unique by convention; the first match wins.
func (s *Server) findApplication(name string) *config.ApplicationConfig {
	for i := range s.cfg.Applications {
		if s.cfg.Applications[i].Name == name {
			return &s.cfg.Applications[i]
		}
	}
	return nil
}

// resolveAppArgs substitutes the connection placeholders into an argument
// template — {host} {port} {user} {password} {machine}. Unknown placeholders
// ride through verbatim (VirtualBox's rule: the agent never guesses).
func resolveAppArgs(args []string, replacements *strings.Replacer) []string {
	resolved := make([]string, 0, len(args))
	for _, arg := range args {
		resolved = append(resolved, replacements.Replace(arg))
	}
	return resolved
}

// handleLaunchApplication serves POST
// /machines/{machineName}/applications/{appName}/launch — SHI's openFtpClient
// generalized (Mark's go 2026-07-12): spawn the configured tool on the AGENT
// host with the machine's live connection details substituted into its
// argument template. Fire-and-forget like every launcher; a missing
// executable is refused up front rather than spawned into the void.
func (s *Server) handleLaunchApplication(w http.ResponseWriter, r *http.Request) {
	application := s.findApplication(r.PathValue("appName"))
	if application == nil {
		taskError(w, http.StatusNotFound,
			"No application by that name is configured (applications[] in the agent configuration)")
		return
	}
	if stat, err := os.Stat(application.Path); err != nil || stat.IsDir() {
		taskError(w, http.StatusBadRequest,
			"Application executable does not exist on the agent host: "+application.Path)
		return
	}

	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return
	}
	machineConfig := machines.ParseConfiguration(machine)
	credentials := machines.ExtractCredentials(machineConfig.Section("settings"))
	host, port := s.sshTransport(r.Context(), machine, machineConfig)
	if host == "" {
		taskError(w, http.StatusBadRequest,
			"No transport to the machine: no NAT ssh port-forward, no guest-agent-reported IP, and no control IP in networks[]")
		return
	}

	args := resolveAppArgs(application.Args, strings.NewReplacer(
		"{host}", host,
		"{port}", strconv.Itoa(port),
		"{user}", credentials.Username,
		"{password}", credentials.Password,
		"{machine}", machine.Name,
	))

	// Detached, like every launcher: the tool outlives the request and its
	// window belongs to the agent host's desktop.
	cmd := exec.CommandContext(context.Background(), application.Path, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	if err := cmd.Start(); err != nil {
		slog.Error("launch application", "application", application.Name,
			"machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to launch "+application.Name+": "+err.Error())
		return
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Warn("application exited with error", "application", application.Name, "error", err)
		}
	}()
	slog.Info("application launched", "application", application.Name,
		"machine", machine.Name, "by", auth.FromContext(r.Context()).Name)

	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"application":  application.Name,
		"host":         host,
		"port":         port,
		"message":      application.Name + " launch requested on the agent host",
	})
}

// handleOpenMachineDirectory serves POST /machines/{name}/open-directory:
// opens the machine's working directory in the agent host's file manager
// (Explorer / Finder / the xdg default).
func (s *Server) handleOpenMachineDirectory(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	if machine.Home == nil || *machine.Home == "" {
		taskError(w, http.StatusBadRequest,
			"Machine has no working directory (discovered VirtualBox-only machines carry none)")
		return
	}
	home := *machine.Home
	if stat, err := os.Stat(home); err != nil || !stat.IsDir() {
		taskError(w, http.StatusNotFound, "Working directory does not exist on this host: "+home)
		return
	}
	openbrowser.Open(home, "")
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"directory":    home,
		"message":      "File manager launch requested on the agent host",
	})
}
