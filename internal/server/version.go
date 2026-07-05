package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/prereqs"
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

func errorResponse(w http.ResponseWriter, status int, errText, details string) {
	payload := map[string]any{
		"success":   false,
		"error":     errText,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if details != "" {
		payload["details"] = details
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

// handleVersion mirrors the Node agent's GET /version, with Go-flavored
// runtime fields and the detected provisioning tools (SHI's footer info).
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	successResponse(w, "Version information retrieved", map[string]any{
		"version":        version.Version,
		"name":           "hyperweaver-agent",
		"go_version":     runtime.Version(),
		"platform":       runtime.GOOS,
		"arch":           runtime.GOARCH,
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
		"tools":          prereqs.Detect(r.Context()),
		"host":           hostinfo.Get(),
	})
}

// handleUpdateCheck mirrors the Node agent's GET /app/updates/check: fetch
// the configured versioninfo document and compare against the running build.
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

	successResponse(w, "Update check completed", map[string]any{
		"current_version":  version.Version,
		"latest_version":   info.Version,
		"update_available": available,
		"release_url":      nullable(info.ReleaseURL),
		"release_date":     nullable(info.ReleaseDate),
		"changelog":        nullable(info.Changelog),
	})
}

// handleProvisioningStatus mirrors the Node agent's GET /provisioning/status:
// a bare tool-name -> installed map (this agent's tools are Vagrant,
// VirtualBox, Git; the Node agent lists its OmniOS set — same endpoint,
// platform-appropriate contents).
func (s *Server) handleProvisioningStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]bool{}
	for _, tool := range prereqs.Detect(r.Context()) {
		status[tool.Name] = tool.Installed
	}
	writeJSON(w, status)
}
