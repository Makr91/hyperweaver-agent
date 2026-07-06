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

// platformFeatures are the capability tokens this agent always advertises
// (the Node agent's PLATFORM_FEATURES model: no config kill-switch).
// machine-suspend is an op-level token (agreed in hyperweaver-ai-sync.md):
// the UI shows Suspend wherever it appears — VirtualBox suspends, bhyve does
// not, and no UI code ever branches on hypervisor values. monitoring and
// processes shipped with the spec-matching pass (arch items 15/16): the
// /monitoring/* endpoints serve realtime samples regardless of the storage
// setting, so the token is unconditional. provisioning shipped with the
// provisioner package registry (/provisioning/provisioners); machine-create
// shipped with the create pipeline (POST /machines → vagrant up through the
// queue). Still to come: artifacts/templates join the config-gated set when
// their subsystems land.
var platformFeatures = []string{
	"tasks", "machines", "machine-suspend", "machine-create", "swap",
	"monitoring", "processes", "provisioning",
}

// features derives the advertised token list: platform tokens plus the
// config-gated ones (Agent API v1 rule — a config-disabled surface is not
// advertised, so token-gating clients never hit its 503s).
func (s *Server) features() []string {
	tokens := make([]string, 0, len(platformFeatures)+1)
	tokens = append(tokens, platformFeatures...)
	if s.cfg.HostPower.Enabled {
		tokens = append(tokens, "host-power")
	}
	return tokens
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
		// Console stays empty until the console phase ships. VNC-capability
		// detection when it does (Mark's recipe, 2026-07-06): parse
		// `VBoxManage list extpacks` — each pack block's "VRDE Module:" line
		// names its remote-display backend (VBoxVNC = VNC extpack, VBoxVRDP =
		// Oracle RDP) and must pair with "Usable: true". The mere presence of
		// a pack proves nothing: Mark's Oracle pack 7.2.12 reports an EMPTY
		// VRDE Module. `VBoxManage list systemproperties` → "Default VRDE ext
		// pack" says which module VMs use (set: VBoxManage setproperty
		// vrdeextpack VNC); per-VM it's `modifyvm --vrde on` + VNC properties.
		// Advertise ["vnc"] only when a usable VBoxVNC module exists.
		Console:  []string{},
		Features: s.features(),
		Uptime:             int64(time.Since(s.startedAt).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write status response", "error", err)
	}
}
