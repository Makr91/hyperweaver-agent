package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/updater"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// Response wrappers matching the Node agent's ResponseHelpers:
// success -> {success:true, message, timestamp, ...data}
// error   -> {success:false, error, timestamp, details?}

func successResponse(w http.ResponseWriter, message string, data map[string]any) {
	payload := map[string]any{
		"success":   true,
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range data {
		payload[k] = v
	}
	writeJSON(w, payload)
}

// wrappedError is the Node agent's error envelope — every errorResponse
// answer (the spec's WrappedError component).
type wrappedError struct {
	Success bool `json:"success"`
	// Error message
	Error string `json:"error"`
	// RFC3339 UTC
	Timestamp string `json:"timestamp"`
	// Optional detail; omitted when empty
	Details string `json:"details,omitempty"`
}

func errorResponse(w http.ResponseWriter, status int, errText, details string) {
	payload := wrappedError{
		Success:   false,
		Error:     errText,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Details:   details,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write error response", "error", err)
	}
}

// nullable maps empty strings to JSON null, matching the Node responses.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

type versionResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	Timestamp     string `json:"timestamp"`
	Version       string `json:"version"`
	Name          string `json:"name"`
	GoVersion     string `json:"go_version"`
	Platform      string `json:"platform"`
	Arch          string `json:"arch"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	// One detected prerequisite (SHI parity: presence + version)
	Tools []prereqs.Tool `json:"tools"`
	Host  hostinfo.Info  `json:"host"`
}

// handleVersion mirrors the Node agent's GET /version, with Go-flavored
// runtime fields and the detected provisioning tools (SHI's footer info).
//
//	@Summary		Application version and host environment
//	@Description	Minimum role: viewer. Includes the detected provisioning prerequisites (Vagrant, VirtualBox, Git, ansible, rsync, scp, plus builtin_sync — the embedded pure-Go transports) and host information — SHI's footer data. The ansible row reports the host's control node: the native binary where the OS carries one, and on Windows the default WSL distribution's ansible (the WSL control-node resolution the remote-playbook and winrm mechanisms use — path names the wsl.exe carrying it).
//	@Tags			System
//	@Produce		json
//	@Success		200	{object}	versionResponse	"Version information"
//	@Router			/version [get]
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, versionResponse{
		Success:       true,
		Message:       "Version information retrieved",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Version:       version.Version,
		Name:          "hyperweaver-agent",
		GoVersion:     runtime.Version(),
		Platform:      runtime.GOOS,
		Arch:          runtime.GOARCH,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		Tools:         prereqs.Detect(r.Context()),
		Host:          hostinfo.Get(),
	})
}

type updateCheckResponse struct {
	Success         bool   `json:"success"`
	Message         string `json:"message"`
	Timestamp       string `json:"timestamp"`
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	ReleaseURL      any    `json:"release_url"`
	ReleaseDate     any    `json:"release_date"`
	Changelog       any    `json:"changelog"`
}

// handleUpdateCheck mirrors the Node agent's GET /app/updates/check: fetch
// the configured versioninfo document and compare against the running build.
//
//	@Summary		Check for application updates
//	@Description	Minimum role: viewer. Fetches the configured versioninfo document (updates.versioninfo_url) and compares against the running build.
//	@Tags			System
//	@Produce		json
//	@Success		200	{object}	updateCheckResponse	"Update check result"
//	@Failure		400	{object}	wrappedError	"Update checking not configured"
//	@Failure		500	{object}	wrappedError	"Versioninfo fetch or parse failure"
//	@Router			/app/updates/check [get]
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	url := s.cfg.Updates.VersionInfoURL
	if url == "" {
		errorResponse(w, http.StatusBadRequest,
			"Update checking not configured", "Set updates.versioninfo_url in configuration")
		return
	}

	info, available, err := updater.Check(r.Context(), url, version.Version)
	if err != nil {
		slog.Error("update check failed", "error", err, "url", url)
		errorResponse(w, http.StatusInternalServerError, "Failed to check for updates", err.Error())
		return
	}

	writeJSON(w, updateCheckResponse{
		Success:         true,
		Message:         "Update check completed",
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		CurrentVersion:  version.Version,
		LatestVersion:   info.Version,
		UpdateAvailable: available,
		ReleaseURL:      nullable(info.ReleaseURL),
		ReleaseDate:     nullable(info.ReleaseDate),
		Changelog:       nullable(info.Changelog),
	})
}

type updateApplyResponse struct {
	Success       bool   `json:"success"`
	TaskID        string `json:"task_id"`
	TargetVersion string `json:"target_version"`
	Status        string `json:"status"`
	Message       string `json:"message"`
}

// handleUpdateApply queues an agent_update task (Mark's ruling 2026-07-06,
// SHI's flow): download this platform's installer from the release, verify
// it against SHA256SUMS.txt, launch it, and exit the agent so the installer
// can take over.
//
//	@Summary		Download and apply an agent update
//	@Description	Minimum role: admin. Queues an agent_update task (SHI's download-then-relaunch, Mark's ruling 2026-07-06): downloads this platform's installer from the release named by updates.versioninfo_url, verifies it against the release's SHA256SUMS.txt (MANDATORY — an unverifiable installer never launches), starts it (the .exe directly on Windows, open for the macOS .pkg, xdg-open for the Linux .deb — headless Linux keeps the download and reports the dpkg command), and exits the agent so the installer can replace it.
//	@Tags			System
//	@Produce		json
//	@Success		202	{object}	updateApplyResponse	"Update task queued"
//	@Failure		400	{object}	wrappedError	"Update checking not configured, or already up to date"
//	@Failure		500	{object}	wrappedError	"Versioninfo fetch failure"
//	@Router			/app/updates/apply [post]
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	url := s.cfg.Updates.VersionInfoURL
	if url == "" {
		errorResponse(w, http.StatusBadRequest,
			"Update checking not configured", "Set updates.versioninfo_url in configuration")
		return
	}
	info, available, err := updater.Check(r.Context(), url, version.Version)
	if err != nil {
		slog.Error("update check failed", "error", err, "url", url)
		errorResponse(w, http.StatusInternalServerError, "Failed to check for updates", err.Error())
		return
	}
	if !available {
		errorResponse(w, http.StatusBadRequest, "Already up to date",
			"Running "+version.Version+", latest is "+info.Version)
		return
	}

	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   updater.OpApply,
		Priority:    tasks.PriorityHigh,
		CreatedBy:   auth.FromContext(r.Context()).Name,
	})
	if err != nil {
		slog.Error("queue agent update", "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to queue update task", err.Error())
		return
	}
	slog.Warn("agent update queued", "target_version", info.Version,
		"by", auth.FromContext(r.Context()).Name)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if werr := json.NewEncoder(w).Encode(updateApplyResponse{
		Success:       true,
		TaskID:        task.ID,
		TargetVersion: info.Version,
		Status:        tasks.StatusPending,
		Message:       "Update task queued — the agent will exit once the installer launches",
	}); werr != nil {
		slog.Error("write update response", "error", werr)
	}
}

// handleProvisioningStatus mirrors the Node agent's GET /provisioning/status:
// a bare tool-name -> installed map (this agent's tools are Vagrant,
// VirtualBox, Git; the Node agent lists its OmniOS set — same endpoint,
// platform-appropriate contents).
//
//	@Summary		Provisioning prerequisite availability
//	@Description	Minimum role: viewer. A bare tool-name → installed map; this agent's tools are vagrant, virtualbox, git, ansible, rsync, scp, and builtin_sync (always true — the embedded pure-Go rsync client + SFTP that make vagrant optional), plus utm on macOS agents ONLY (never reported off darwin). rsync/scp probe with the pipeline's own lookup: PATH, vagrant's embedded toolchain, and the Windows OpenSSH directory. ansible probes the host control node — the native binary, or on Windows the default WSL distribution's ansible-playbook (the transports matrix's WSL rows). (The Node agent lists its OmniOS set — same endpoint, platform-appropriate contents.)
//	@Tags			System
//	@Produce		json
//	@Success		200	{object}	map[string]bool	"Tool availability map"
//	@Router			/provisioning/status [get]
func (s *Server) handleProvisioningStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]bool{}
	for _, tool := range prereqs.Detect(r.Context()) {
		status[tool.Name] = tool.Installed
	}
	writeJSON(w, status)
}
