package server

import (
	"context"
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
	// SHIMode advertises the "I Can't Believe it's not Super.Human.Installer"
	// presentation toggle (ui.shi_mode) — Direct-mode UI theming; absent/false
	// on agents without the concept.
	SHIMode bool  `json:"shi_mode"`
	Uptime  int64 `json:"uptime"`
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
// shipped with the create orchestration (POST /machines → native VBoxManage build through the
// queue; the zoneweaver mechanism, no vagrant). provisioner-registry and secrets are the finer tokens of Mark's
// gating ruling (2026-07-06): zoneweaver's provisioning/machine-create are
// equally TRUE but name different wire shapes, so the SHI-format registry
// surface (/provisioning/provisioners*) and the global secrets store
// (/secrets) advertise their own tokens — zoneweaver gains each when its
// parity lands, and the UI's Installer Files gate is artifacts ∧
// provisioner-registry. templates shipped with the box-template registry
// (the create orchestration's storage source) — always on here; zoneweaver
// config-gates its counterpart on template_sources.enabled. machine-modify
// shipped with the machine_modify port of zoneweaver's PUT modify (the UI's
// Edit modal gates on it; zoneweaver adds it in its own session).
// machine-snapshots shipped with the VBoxManage snapshot family
// (/machines/{name}/snapshots — list/take/restore/delete + clone
// source=current); machine-screenshot with the no-session framebuffer PNG
// (GET /machines/{name}/vnc/screenshot — zoneweaver serves the same endpoint
// from the bhyve framebuffer and gains the token in its own session).
var platformFeatures = []string{
	"tasks", "machines", "machine-suspend", "machine-create",
	"machine-modify", "machine-snapshots", "machine-screenshot",
	"swap", "monitoring", "processes", "provisioning",
	"provisioner-registry", "secrets", "templates",
}

// features derives the advertised token list: platform tokens plus the
// config-gated ones (Agent API v1 rule — a config-disabled surface is not
// advertised, so token-gating clients never hit its 503s).
func (s *Server) features() []string {
	tokens := make([]string, 0, len(platformFeatures)+2)
	tokens = append(tokens, platformFeatures...)
	if s.cfg.HostPower.Enabled {
		tokens = append(tokens, "host-power")
	}
	if s.cfg.Assets.Enabled {
		tokens = append(tokens, "artifacts")
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

// consoles derives the advertised console list: ssh always (the terminal
// surface has no extra requirement), vnc when a usable VBoxVNC module exists.
func (s *Server) consoles(ctx context.Context) []string {
	list := []string{"ssh"}
	if vncConsoleAvailable(ctx) {
		list = append(list, "vnc")
	}
	return list
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
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
		// ssh shipped with the SSH terminal sessions (POST
		// /machines/{name}/ssh/start + the /ssh/{id} WebSocket); vnc
		// advertises only when a usable VBoxVNC VRDE module exists (the
		// detection recipe above — the websockify bridge needs RFB on the
		// VRDE port).
		Console:  s.consoles(r.Context()),
		Features: s.features(),
		SHIMode:  s.cfg.UI.SHIMode,
		Uptime:   int64(time.Since(s.startedAt).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write status response", "error", err)
	}
}
