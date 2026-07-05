package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/version"
)

// statusPayload is the public identity + capabilities document of the
// Hyperweaver dual-mode contract (Agent API v1). Field names and semantics
// mirror the Zoneweaver Agent's StatusController exactly.
type statusPayload struct {
	Role               string   `json:"role"`
	Agent              string   `json:"agent"`
	Hypervisors        []string `json:"hypervisors"`
	Platform           string   `json:"platform"`
	Arch               string   `json:"arch"`
	Version            string   `json:"version"`
	Hostname           string   `json:"hostname"`
	Auth               []string `json:"auth"`
	BootstrapAvailable bool     `json:"bootstrapAvailable"`
	Console            []string `json:"console"`
	Features           []string `json:"features"`
	Uptime             int64    `json:"uptime"`
}

// archName maps Go architecture names to the Agent API contract values.
func archName() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Mirror the exact availability check the bootstrap endpoint enforces.
	akCfg := s.cfg.APIKeys
	bootstrapAvailable := akCfg.BootstrapEnabled &&
		(s.keys.Count() == 0 || !akCfg.BootstrapAutoDisable)

	payload := statusPayload{
		Role:        "agent",
		Agent:       "hyperweaver-agent",
		Hypervisors: []string{"virtualbox"},
		Platform:    runtime.GOOS,
		Arch:        archName(),
		Version:     version.Version,
		Hostname:    hostname,
		// Shared auth-token namespace {apikey, local, ldap, oidc}: this agent
		// accepts API keys ('apikey', never 'local' — different login form).
		Auth:               []string{"apikey"},
		BootstrapAvailable: bootstrapAvailable,
		Console:            []string{},
		Features:           []string{},
		Uptime:             int64(time.Since(s.startedAt).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write status response", "error", err)
	}
}
