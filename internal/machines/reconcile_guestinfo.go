package machines

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/qga"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// refreshGuestInfo records one machine's live-IP observation on its row —
// configuration.guest_info {ips[], source, agent_responding, checked_at}.
// A RUNNING machine's QGA channel is probed first (guest_agent.enabled; 3s —
// qemu-ga answers in milliseconds, the timeout only bites channels nothing
// listens on); when it yields nothing, the Guest Additions' live IP
// properties are the fallback — the SAME two live sources the RDP/SSH target
// ladders dial, and NEVER the provisioning-plan control IP (Mark's ruling
// 2026-07-11: a plan address nothing answers must not present as live).
// Non-running machines lose the section — honest absence ungates the UI's
// direct-connect buttons. existing may be nil (first sight): the pipe then
// derives from the machines root, the same fallback the on-demand handlers
// use, so both sides always address the same channel.
func (r *Reconciler) refreshGuestInfo(ctx context.Context, vboxExe, target, name string,
	existing *Machine, status string, narrate func(stream, line string),
) {
	if status != StatusRunning {
		if err := r.store.SetGuestInfo(ctx, name, nil); err != nil && !errors.Is(err, ErrNotFound) {
			mlog().Warn("clear guest info failed", "machine", name, "error", err)
		}
		return
	}

	ips := []string{}
	source := ""
	responding := false
	if r.guestAgent {
		workdir := ""
		if existing != nil && existing.Home != nil {
			workdir = *existing.Home
		}
		if workdir == "" {
			workdir = filepath.Join(r.machinesDir, provisioner.MachineDirName(name))
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		agentIPs, err := qga.GuestIPv4s(probeCtx, qga.PipePath(workdir, name))
		cancel()
		responding = err == nil
		if len(agentIPs) > 0 {
			ips = agentIPs
			source = "guest-agent"
		}
	}
	if len(ips) == 0 {
		if entries, err := vbox.EnumerateGuestProperties(ctx, vboxExe, target); err == nil {
			for _, entry := range entries {
				if GuestPropertyIPName.MatchString(entry.Name) && UsableGuestIP(entry.Value) {
					ips = append(ips, entry.Value)
				}
			}
			if len(ips) > 0 {
				source = "additions"
			}
		}
	}

	switch {
	case len(ips) > 0:
		narrate("stdout", name+": guest IPs ("+source+"): "+strings.Join(ips, ", "))
	case responding:
		narrate("stdout", name+": guest agent responding, no host-reachable IP yet")
	default:
		narrate("stdout", name+": no live guest IP source (guest agent silent, no Additions)")
	}
	if serr := r.store.SetGuestInfo(ctx, name, map[string]any{
		"ips":              ips,
		"source":           source,
		"agent_responding": responding,
		"checked_at":       time.Now().UTC().Format(time.RFC3339),
	}); serr != nil {
		narrate("stderr", name+": storing guest info failed ("+serr.Error()+")")
		mlog().Warn("store guest info failed", "machine", name, "error", serr)
	}
}

// refreshGuestInfoUTM is refreshGuestInfo's utm twin: the one live source is
// utmctl ip-address (qemu-guest-agent — no UART, no Additions fallback);
// non-running machines lose the section exactly like VBox rows.
func (r *Reconciler) refreshGuestInfoUTM(ctx context.Context, utmctlPath, target, name, status string,
	narrate func(stream, line string),
) {
	if status != StatusRunning {
		if err := r.store.SetGuestInfo(ctx, name, nil); err != nil && !errors.Is(err, ErrNotFound) {
			mlog().Warn("clear guest info failed", "machine", name, "error", err)
		}
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	agentIPs, err := utm.GuestIPs(probeCtx, utmctlPath, target)
	cancel()
	responding := err == nil
	ips := []string{}
	for _, ip := range agentIPs {
		if UsableGuestIP(ip) {
			ips = append(ips, ip)
		}
	}
	source := ""
	if len(ips) > 0 {
		source = "guest-agent"
	}

	switch {
	case len(ips) > 0:
		narrate("stdout", name+": guest IPs ("+source+"): "+strings.Join(ips, ", "))
	case responding:
		narrate("stdout", name+": guest agent responding, no host-reachable IP yet")
	default:
		narrate("stdout", name+": no live guest IP source (qemu-guest-agent silent)")
	}
	if serr := r.store.SetGuestInfo(ctx, name, map[string]any{
		"ips":              ips,
		"source":           source,
		"agent_responding": responding,
		"checked_at":       time.Now().UTC().Format(time.RFC3339),
	}); serr != nil {
		narrate("stderr", name+": storing guest info failed ("+serr.Error()+")")
		mlog().Warn("store guest info failed", "machine", name, "error", serr)
	}
}
