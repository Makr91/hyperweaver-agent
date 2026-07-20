package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
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
// host-launchers shipped with the SHI open-directory/open-FTP parity (Mark's
// both-ways ruling 2026-07-07): agent-host launch endpoints + the /ftp info
// endpoint — meaningful UI only in Direct desktop mode, but always truthful.
// host-terminal shipped with the /term family (Mark's go 2026-07-07): a
// shell on the agent host itself, admin-only, over the platform PTY
// (creack/pty on Unix, ConPTY on Windows).
// ssh is a FEATURE, not a console (Mark's placement ruling 2026-07-12):
// console[] carries EMERGENCY consoles only — hypervisor-level surfaces that
// work with zero guest cooperation (VRDE rdp here; vnc/zlogin on bhyve). The
// machine SSH terminal rides the guest's own network and credentials, so it
// advertises as features:ssh — zoneweaver's home, now shared.
// hosts-file minted 2026-07-17 (Mark's pick on the UI's gating open): the
// /system/hosts editor ships on BOTH agents with the converged wire, so it
// advertises as a platform token — the UI gates the Host tab on it (D14's
// gate-on-tokens-only rule).
// dns minted 2026-07-17: the /system/dns surface with the converged wire —
// per-OS mechanics (resolv.conf on Unix, netsh on Windows, networksetup on
// macOS), wire identical; the UI's Network-tab DNS section gates on it.
// hostname minted 2026-07-17: the /network/hostname surface (GET live view
// + PUT queuing set_hostname) with the converged wire.
// ip-addresses minted 2026-07-17: the /network/addresses surface — the live
// listing plus (Mark's build order 2026-07-19, replacing the 501 stubs) the
// zoneweaver-converged mutations: create (static everywhere, dhcp on
// Windows), delete, and the interface-level enable/disable toggles.
// network-spaces minted 2026-07-19 (the UI topology ask): the
// /network/spaces surface — enumerate + manage VirtualBox's host-only
// interfaces, NAT networks, and internal networks; the topology mapper
// gates its network-space fetch on this token (D14: tokens, never
// hypervisors[]).
var platformFeatures = []string{
	"tasks", "machines", "machine-suspend", "machine-create",
	"machine-modify", "machine-snapshots", "machine-screenshot",
	"swap", "monitoring", "processes", "provisioning",
	"provisioner-registry", "secrets", "ssh", "templates",
	"host-launchers", "host-terminal", "hosts-file", "dns",
	"hostname", "ip-addresses", "network-spaces",
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
	if s.cfg.ArtifactStorage.Enabled {
		tokens = append(tokens, "artifacts")
	}
	if s.cfg.FileBrowser.Enabled {
		tokens = append(tokens, "file-browser")
	}
	if s.cfg.GuestAgent.Enabled {
		tokens = append(tokens, "guest-agent")
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

// utmCapability caches the utm hypervisor probe (the vncCapability pattern —
// utm.Version shells osascript, too costly per /status poll). Restart the
// agent after installing or upgrading UTM.
var (
	utmCapabilityOnce sync.Once
	utmCapable        bool
)

// utmHypervisorAvailable reports whether this host can drive utm machines:
// darwin ∧ utmctl present ∧ UTM version at the 4.6.5 floor. Shared by the
// /status hypervisors list and the remote-catalog provider filter.
func utmHypervisorAvailable(ctx context.Context) bool {
	utmCapabilityOnce.Do(func() {
		if runtime.GOOS != "darwin" || machines.UTMCtlPath(ctx) == "" {
			return
		}
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		utmVersion, err := utm.Version(probeCtx)
		utmCapable = err == nil && utm.VersionSupported(utmVersion)
	})
	return utmCapable
}

// hypervisors derives the advertised hypervisor list: virtualbox always, utm
// when the capability probe passes.
func (s *Server) hypervisors(ctx context.Context) []string {
	list := []string{"virtualbox"}
	if utmHypervisorAvailable(ctx) {
		list = append(list, "utm")
	}
	return list
}

// consoles derives the advertised console list — EMERGENCY consoles only
// (Mark's placement ruling 2026-07-12): rdp always (base VRDP ships in
// VirtualBox 7.2 and the RDCleanPath bridge is built in — the IronRDP web
// client's transport), vnc when a usable VBoxVNC module exists. The SSH
// terminal is guest-network access and advertises as features:ssh.
func (s *Server) consoles(ctx context.Context) []string {
	list := []string{"rdp"}
	if vncConsoleAvailable(ctx) {
		list = append(list, "vnc")
	}
	return list
}

// @Summary		Public identity and capabilities
// @Description	Canonical path of the public status probe. No authentication.
// @Tags			Status
// @Produce		json
// @Success		200	{object}	statusPayload	"Agent identity and capabilities"
// @Router			/status [get]
// @Router			/api/status [get]
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
		Hypervisors: s.hypervisors(r.Context()),
		Platform:    runtime.GOOS,
		Arch:        archName(),
		Version:     version.Version,
		Hostname:    hostname,
		// Shared auth-token namespace {apikey, local, ldap, oidc}: this agent
		// accepts API keys ('apikey', never 'local' — different login form).
		Auth:               []string{"apikey"},
		BootstrapAvailable: bootstrapAvailable,
		// VNC-capability detection (Mark's recipe, 2026-07-06): parse
		// `VBoxManage list extpacks` — each pack block's "VRDE Module:" line
		// names its remote-display backend (VBoxVNC = VNC extpack, VBoxVRDP =
		// Oracle RDP) and must pair with "Usable: true". The mere presence of
		// a pack proves nothing: Mark's Oracle pack 7.2.12 reports an EMPTY
		// VRDE Module. Advertise vnc only when a usable VBoxVNC module exists
		// (the websockify bridge needs RFB on the VRDE port).
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
