// Package hostname implements the set_hostname task executor (the
// /network/hostname surface's async half — the converged wire, sync
// 2026-07-17: zoneweaver's exact op name, queued MachineName "system").
// Per-platform apply with per-platform honesty (Mark's ruling: "surface
// requires_restart honestly where the OS demands it"):
//   - Linux: `hostnamectl set-hostname` (live apply); when hostnamectl is
//     absent, write /etc/hostname and run `hostname <name>` — same effect.
//   - macOS: `scutil --set HostName` + LocalHostName (sanitized single
//     label) + ComputerName — all three names converge, live.
//   - Windows: PowerShell `Rename-Computer -Force` — the rename lands at
//     the NEXT REBOOT, and the task narrates exactly that; apply_immediately
//     cannot be honored live on this platform.
package hostname

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// Op is the hostname task operation (zoneweaver's exact op name — the
// converged wire, sync 2026-07-17).
const Op = "set_hostname"

// labelPattern is one RFC-1123 hostname label: letters/digits/hyphens,
// no leading or trailing hyphen, 1–63 characters.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Metadata is the set_hostname task's metadata document.
type Metadata struct {
	// Hostname is the new name — RFC-1123 label(s), dots allowed.
	Hostname string `json:"hostname"`
	// ApplyImmediately asks for a live apply. Linux/macOS apply live
	// inherently; Windows cannot (reboot semantics) and narrates that.
	ApplyImmediately bool `json:"apply_immediately"`
}

// MetadataJSON serializes task metadata for the queue.
func MetadataJSON(m Metadata) (*string, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// Valid reports whether name is RFC-1123 legal: dot-separated labels of
// letters/digits/hyphens (no leading/trailing hyphen per label), 253
// characters total at most.
func Valid(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// RegisterExecutors wires the set_hostname operation into the task queue.
func RegisterExecutors(queue *tasks.Queue) {
	queue.Register(Op, tasks.Executor{Run: setHostname})
}

// setHostname executes one set_hostname task: re-validate the name
// (defense in depth — the HTTP handler validated it once already) and
// apply it through the platform's own tooling.
func setHostname(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta Metadata
	if task.Metadata == nil {
		return errors.New("set_hostname task has no metadata")
	}
	if err := json.Unmarshal([]byte(*task.Metadata), &meta); err != nil {
		return fmt.Errorf("parse set_hostname metadata: %w", err)
	}
	if !Valid(meta.Hostname) {
		return fmt.Errorf("hostname %q is not RFC-1123 legal", meta.Hostname)
	}

	switch runtime.GOOS {
	case "windows":
		return applyWindows(ctx, meta, out)
	case "darwin":
		return applyDarwin(ctx, meta, out)
	default:
		return applyLinux(ctx, meta, out)
	}
}

// applyWindows renames the computer via PowerShell Rename-Computer. The
// rename lands at the next reboot — Windows offers no live hostname apply,
// so apply_immediately is narrated as unhonorable, never silently dropped.
func applyWindows(ctx context.Context, meta Metadata, out *tasks.OutputWriter) error {
	if meta.ApplyImmediately {
		out.Write("stdout", "apply_immediately cannot be honored on Windows — the rename takes effect at the next reboot\n")
	}
	if err := runTool(ctx, out, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Rename-Computer -NewName '"+meta.Hostname+"' -Force"); err != nil {
		return err
	}
	out.Write("stdout", "Computer renamed to "+meta.Hostname+" — the new name takes effect at the next reboot\n")
	return nil
}

// applyDarwin sets all three macOS names via scutil (live apply):
// HostName and ComputerName verbatim, LocalHostName as a sanitized single
// label (Bonjour allows one RFC-1123 label only).
func applyDarwin(ctx context.Context, meta Metadata, out *tasks.OutputWriter) error {
	if err := runTool(ctx, out, "scutil", "--set", "HostName", meta.Hostname); err != nil {
		return err
	}
	if err := runTool(ctx, out, "scutil", "--set", "LocalHostName", localLabel(meta.Hostname)); err != nil {
		return err
	}
	if err := runTool(ctx, out, "scutil", "--set", "ComputerName", meta.Hostname); err != nil {
		return err
	}
	out.Write("stdout", "Hostname set to "+meta.Hostname+" (applied live)\n")
	return nil
}

// applyLinux applies via hostnamectl (persists AND applies live on systemd
// hosts); when hostnamectl is absent, write /etc/hostname for persistence
// and run `hostname <name>` for the live half — the same end state.
func applyLinux(ctx context.Context, meta Metadata, out *tasks.OutputWriter) error {
	if _, lerr := exec.LookPath("hostnamectl"); lerr == nil {
		if err := runTool(ctx, out, "hostnamectl", "set-hostname", meta.Hostname); err != nil {
			return err
		}
		out.Write("stdout", "Hostname set to "+meta.Hostname+" (applied live)\n")
		return nil
	}
	out.Write("stdout", "hostnamectl not found — writing /etc/hostname and applying with hostname(1)\n")
	if werr := safepath.WriteFile("/etc/hostname", []byte(meta.Hostname+"\n"), 0o644); werr != nil {
		return fmt.Errorf("write /etc/hostname: %w", werr)
	}
	if err := runTool(ctx, out, "hostname", meta.Hostname); err != nil {
		return err
	}
	out.Write("stdout", "Hostname set to "+meta.Hostname+" (applied live)\n")
	return nil
}

// localLabel sanitizes a name into one Bonjour-legal RFC-1123 label: the
// first dot-separated label with every illegal character dropped.
func localLabel(name string) string {
	label, _, _ := strings.Cut(name, ".")
	var b strings.Builder
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	cleaned := strings.Trim(b.String(), "-")
	if cleaned == "" {
		return "hyperweaver-host"
	}
	if len(cleaned) > 63 {
		cleaned = strings.Trim(cleaned[:63], "-")
	}
	return cleaned
}

// runTool executes one platform command, streaming its combined output
// into the task output (the hostpower package's shape).
func runTool(ctx context.Context, out *tasks.OutputWriter, name string, args ...string) error {
	out.Write("stdout", "Executing: "+name+" "+strings.Join(args, " ")+"\n")
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	combined, cerr := cmd.CombinedOutput()
	if len(combined) > 0 {
		out.Write("stdout", string(combined))
	}
	if cerr != nil {
		out.Write("stderr", "Hostname command failed: "+cerr.Error()+"\n")
		return fmt.Errorf("set_hostname %s: %w", name, cerr)
	}
	return nil
}
