package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/sslcert"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// agentCAPool loads the agent CA — the VRDE certificate's trust root (the
// vrde-tls setup mints from it; BYO material must chain to it too).
func (s *Server) agentCAPool() (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(s.cfg.SSLCACertPath()))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("agent CA certificate is not PEM")
	}
	return pool, nil
}

// vrdeCertDir is where a machine's minted VRDE TLS material lives: beside
// the agent's own ssl tree, surviving as long as the configuration does
// (the create executor mints into the same root).
func (s *Server) vrdeCertDir(machineName string) string {
	return filepath.Join(s.cfg.VRDECertRoot(), machineName)
}

// vrdeTLSProperties mints (or reuses) the machine's VRDE TLS material and
// answers the four Security properties in name=value form — the ONE list the
// live self-heal, the setup endpoint, and the queued modify all speak.
func (s *Server) vrdeTLSProperties(machineName string) (certPath string, properties []string, err error) {
	certPath, keyPath, caPath, err := sslcert.EnsureVRDECertificate(
		s.cfg.SSLCACertPath(), s.cfg.SSLCAKeyPath(),
		s.vrdeCertDir(machineName), machineName)
	if err != nil {
		return "", nil, err
	}
	return certPath, []string{
		"Security/Method=Negotiate",
		"Security/ServerCertificate=" + certPath,
		"Security/ServerPrivateKey=" + keyPath,
		"Security/CACertificate=" + caPath,
	}, nil
}

// healVRDETLS applies the VRDE TLS setup to a RUNNING machine LIVE:
// controlvm vrdeproperty — the VRDP server queries Security/* per client
// connection (VirtualBox-source-verified + runtime-proven on Mark's 7.2,
// 2026-07-11), so the properties take effect for the NEXT connect with no
// power cycle, and they persist into the machine settings like modifyvm's.
// Applying restarts the VRDE listener (existing RDP sessions drop; the VM
// is untouched).
func (s *Server) healVRDETLS(ctx context.Context, vboxExe string, machine *machines.Machine) error {
	_, properties, err := s.vrdeTLSProperties(machine.Name)
	if err != nil {
		return err
	}
	for _, property := range properties {
		if perr := vbox.ControlVMArgs(ctx, vboxExe, machine.VBoxTarget(), "vrdeproperty", property); perr != nil {
			return perr
		}
	}
	return nil
}

// handleVRDETLSSetup serves POST /machines/{machineName}/vrde-tls — turnkey
// Enhanced-security VRDE (the browser-RDP path's floor): mints the machine's
// VRDE certificate from the agent CA and pushes the VRDE TLS properties —
// plus VRDE itself when off — RUNNING machines get the security properties
// LIVE (controlvm vrdeproperty; no power cycle) with the modifyvm-bound
// extras accrued; powered-off machines get everything as a queued modify.
// Near-obsolete since the bridge self-heals and create mints from birth —
// kept as the explicit prep path. Method stays Negotiate so mstsc and other
// native clients keep connecting however they like; the bridge always asks
// for TLS and gets it.
//
//	@Summary		Set up VRDE TLS (Enhanced RDP Security)
//	@Description	Minimum role: operator. Explicit VRDE TLS prep — NEAR-OBSOLETE since machine creation mints the TLS material from birth and the rdp-bridge SELF-HEALS unconfigured machines live at first connect (Mark's zero-click ruling 2026-07-11); kept as the manual prep path. Mints the machine's VRDE certificate signed by the AGENT CA (loopback SANs; files under <config dir>/ssl/vrde/<machine>/ — reused, never regenerated) and applies Security/Method=Negotiate + the certificate/key/CA paths. RUNNING machines: applied LIVE via controlvm vrdeproperty (status applied_live, requires_restart false — the VRDP server reads Security/* per connection; the VRDE listener restarts, dropping active RDP sessions, VM untouched), with the modifyvm-bound console extras (multi-con, reuse-con, usbtablet, usb keyboard, xHCI, clipboard) accrued for the next power cycle (pending_changes in the answer). POWERED-OFF machines: everything as one queued machine_modify. Negotiate keeps native clients (mstsc) connecting however they like; the bridge always asks for TLS and gets it.
//	@Tags			Console
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"TLS applied live (running), setup queued (powered off), or accrued (live apply failed)"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/vrde-tls [post]
func (s *Server) handleVRDETLSSetup(w http.ResponseWriter, r *http.Request) {
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
		slog.Error("vrde-tls probe", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to read machine state")
		return
	}

	certPath, securityProperties, err := s.vrdeTLSProperties(machine.Name)
	if err != nil {
		slog.Error("vrde certificate generation", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to generate the VRDE certificate: "+err.Error())
		return
	}

	securityDirectives := make([]any, 0, len(securityProperties))
	for _, property := range securityProperties {
		securityDirectives = append(securityDirectives,
			map[string]any{"directive": "vrde-property", "value": property})
	}
	extraDirectives := []any{
		// Parallel console sessions: without this a browser reconnect (the old
		// TCP still lingering) or a second client answers "AUTH: Multiple
		// connections are not enabled" (Mark's ask 2026-07-10); reuse-con
		// keeps the guest session across reconnects (the bridge opens a fresh
		// WS per console open — Mark's directive after live testing).
		map[string]any{"directive": "vrde-multi-con", "value": "on"},
		map[string]any{"directive": "vrde-reuse-con", "value": "on"},
		// The browser-console input/clipboard defaults (Mark's directive
		// 2026-07-10): absolute pointer, USB keyboard, xHCI, clipboard both
		// ways — the machine was EXPLICITLY being prepped for browser
		// consoles, so the input experience comes along.
		map[string]any{"directive": "mouse", "value": "usbtablet"},
		map[string]any{"directive": "keyboard", "value": "usb"},
		map[string]any{"directive": "usb-xhci", "value": "on"},
		map[string]any{"directive": "clipboard-mode", "value": "bidirectional"},
		map[string]any{"directive": "clipboard-file-transfers", "value": "enabled"},
	}
	doc := map[string]any{"vbox": map[string]any{"directives": append(append([]any{}, securityDirectives...), extraDirectives...)}}
	if info.Raw["vrde"] != "on" {
		doc["vnc"] = "on"
	}

	// RUNNING machines get the security properties applied LIVE (controlvm
	// vrdeproperty — Mark's zero-click ruling 2026-07-11): the next connect
	// negotiates TLS, no power cycle. Only the modifyvm-bound extras (input,
	// clipboard, multi-con) still accrue. A live-apply failure falls back to
	// accruing the whole set — today's behavior, honestly reported.
	if machines.MapVBoxState(info.State) == machines.StatusRunning {
		exe := machines.VBoxManagePath(r.Context())
		applyErr := error(nil)
		for _, property := range securityProperties {
			if perr := vbox.ControlVMArgs(r.Context(), exe, machine.VBoxTarget(), "vrdeproperty", property); perr != nil {
				applyErr = perr
				break
			}
		}
		if applyErr == nil {
			extrasDoc := map[string]any{"vbox": map[string]any{"directives": extraDirectives}}
			if info.Raw["vrde"] != "on" {
				extrasDoc["vnc"] = "on"
			}
			merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, extrasDoc)
			if merr != nil {
				slog.Error("accrue vrde-tls extras", "machine", machine.Name, "error", merr)
				taskError(w, http.StatusInternalServerError, "TLS applied live, but storing the console extras failed")
				return
			}
			slog.Info("vrde tls applied live", "machine", machine.Name, "by", auth.FromContext(r.Context()).Name)
			writeJSON(w, map[string]any{
				"success":          true,
				"machine_name":     machine.Name,
				"operation":        machines.OpModify,
				"status":           "applied_live",
				"requires_restart": false,
				"pending_changes":  merged,
				"certificate":      certPath,
				"message":          "VRDE TLS applied LIVE — the next connect negotiates Enhanced security. Console input/clipboard extras accrued for the next power cycle.",
			})
			return
		}
		slog.Warn("vrde tls live apply failed — accruing instead", "machine", machine.Name, "error", applyErr)
	}

	switch machines.MapVBoxState(info.State) {
	case machines.StatusStopped, machines.StatusAborted:
		metadata, merr := json.Marshal(doc)
		if merr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to queue the VRDE TLS setup")
			return
		}
		metadataStr := string(metadata)
		task, terr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: machine.Name,
			Operation:   machines.OpModify,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
			Metadata:    &metadataStr,
		})
		if terr != nil {
			slog.Error("queue vrde-tls task", "machine", machine.Name, "error", terr)
			taskError(w, http.StatusInternalServerError, "Failed to queue the VRDE TLS setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"task_id":          task.ID,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           tasks.StatusPending,
			"requires_restart": true,
			"certificate":      certPath,
			"message":          "VRDE TLS setup queued — the certificate is minted and the VRDE properties apply now (machine is powered off).",
		})
	default:
		merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, doc)
		if merr != nil {
			slog.Error("accrue vrde-tls changes", "machine", machine.Name, "error", merr)
			taskError(w, http.StatusInternalServerError, "Failed to store the VRDE TLS setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           "pending_power_cycle",
			"requires_restart": true,
			"pending_changes":  merged,
			"certificate":      certPath,
			"message":          "VRDE TLS setup accrued — the certificate is minted; the VRDE properties apply at the next agent-driven power cycle (stop, start, or restart).",
		})
	}
}
