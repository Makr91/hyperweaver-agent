// Package prereqs detects the external tools the provisioning engine drives
// (Vagrant, VirtualBox, Git, ansible, rsync, scp) — SHI parity: presence +
// version display. rsync's version also feeds the sync-method platform rule (macOS
// auto-falls back to SCP when the system rsync is the ancient Apple 2.x
// build). The sync transports probe with the SAME lookup the pipeline uses
// (sshrun.FindTool: PATH → vagrant's embedded toolchain → Windows OpenSSH),
// so this surface never claims a tool is missing that the pipeline would
// happily use — and builtin_sync reports the always-available pure-Go
// transports (embedded rsync client + SFTP), the reason vagrant is optional.
package prereqs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/ansiblehost"
	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
)

// Tool is one detected prerequisite.
type Tool struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
}

var versionPattern = regexp.MustCompile(`\d+\.\d+[\w.\-]*`)

// Detection results change rarely and probing spawns subprocesses — cache.
const cacheTTL = time.Minute

var (
	cacheMu   sync.Mutex
	cached    []Tool
	cachedAt  time.Time
	probeSpan = 10 * time.Second
)

// Detect probes all prerequisites, serving from a short-lived cache.
func Detect(ctx context.Context) []Tool {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if cached != nil && time.Since(cachedAt) < cacheTTL {
		out := make([]Tool, len(cached))
		copy(out, cached)
		return out
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeSpan)
	defer cancel()

	tools := []Tool{
		probePath(probeCtx, "vagrant", lookPath("vagrant"), "--version"),
		probePath(probeCtx, "virtualbox", lookupVirtualBox(), "--version"),
	}
	// utm reports on darwin ONLY (Mark via sync 2026-07-19 — no row off
	// macOS). utmctl has no version flag — a bare invocation proves presence;
	// UTM's version answers through System Events.
	if runtime.GOOS == "darwin" {
		utmTool := probePath(probeCtx, "utm", lookupUTMCtl())
		if utmTool.Installed {
			if utmVersion, err := utm.Version(probeCtx); err == nil {
				utmTool.Version = utmVersion
			}
		}
		tools = append(tools, utmTool)
	}
	tools = append(tools,
		probePath(probeCtx, "git", lookPath("git"), "--version"),
		ansibleTool(probeCtx),
		probePath(probeCtx, "rsync", lookSyncTool("rsync"), "--version"),
		// OpenSSH scp has no version flag; a bare invocation proves presence.
		probePath(probeCtx, "scp", lookSyncTool("scp")),
		// The embedded pure-Go transports ship inside the agent binary.
		Tool{Name: "builtin_sync", Installed: true, Version: "embedded rsync client + sftp"},
	)

	cached = tools
	cachedAt = time.Now()

	out := make([]Tool, len(tools))
	copy(out, tools)
	return out
}

// ansibleTool reports the host's ansible control node: the native binary
// where the OS carries one, and on Windows the default WSL distribution's
// ansible (the same resolution the remote-playbook and winrm mechanisms use
// — internal/ansiblehost), Path naming the wsl.exe that carries it.
func ansibleTool(ctx context.Context) Tool {
	if runtime.GOOS != "windows" {
		return probePath(ctx, "ansible", lookPath("ansible"), "--version")
	}
	installed, version, wslPath := ansiblehost.DetectWSL(ctx)
	if !installed {
		return Tool{Name: "ansible", Installed: false}
	}
	return Tool{Name: "ansible", Installed: true, Version: version, Path: wslPath}
}

// lookSyncTool locates a sync transport with the pipeline's own lookup
// (sshrun.FindTool) so the reported state matches what a sync task would
// actually find — the PATH-only probe used to claim rsync was missing while
// vagrant's embedded rsync carried every sync.
func lookSyncTool(name string) string {
	if path, err := sshrun.FindTool(name); err == nil {
		return path
	}
	return ""
}

func lookPath(binary string) string {
	if p, err := exec.LookPath(binary); err == nil {
		return p
	}
	// GUI-launched apps on macOS get a minimal PATH that misses the usual
	// install locations — Genesis (SHI's detection layer) prepends
	// /usr/local/bin for the same reason; Homebrew on Apple Silicon adds one.
	if runtime.GOOS == "darwin" {
		for _, dir := range []string{"/usr/local/bin", "/opt/homebrew/bin"} {
			if exe, err := safepath.ValidateExecutable(filepath.Join(dir, binary)); err == nil {
				return exe
			}
		}
	}
	return ""
}

// lookupVirtualBox finds VBoxManage: PATH first, then the Windows install
// locations (the VirtualBox installer does not add itself to PATH). Every
// candidate outside PATH is validated before use — the VBOX_* variables are
// environment input.
func lookupVirtualBox() string {
	if p := lookPath("VBoxManage"); p != "" {
		return p
	}
	if runtime.GOOS != "windows" {
		return ""
	}
	var candidates []string
	for _, env := range []string{"VBOX_MSI_INSTALL_PATH", "VBOX_INSTALL_PATH"} {
		if v := os.Getenv(env); v != "" {
			candidates = append(candidates, filepath.Join(v, "VBoxManage.exe"))
		}
	}
	candidates = append(candidates, `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`)
	for _, candidate := range candidates {
		if exe, err := safepath.ValidateExecutable(candidate); err == nil {
			return exe
		}
	}
	return ""
}

// lookupUTMCtl finds utmctl: PATH first, then UTM.app's bundled binary (UTM
// does not add itself to PATH). Empty anywhere but macOS — UTM is
// darwin-only.
func lookupUTMCtl() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	if p := lookPath("utmctl"); p != "" {
		return p
	}
	if exe, err := safepath.ValidateExecutable("/Applications/UTM.app/Contents/MacOS/utmctl"); err == nil {
		return exe
	}
	return ""
}

// probePath validates the tool binary, then runs its version command and
// extracts a version string.
func probePath(ctx context.Context, name, path string, args ...string) Tool {
	if path == "" {
		return Tool{Name: name, Installed: false}
	}
	exe, err := safepath.ValidateExecutable(path)
	if err != nil {
		return Tool{Name: name, Installed: false}
	}

	tool := Tool{Name: name, Installed: true, Path: exe}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return tool
	}

	firstLine := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if match := versionPattern.FindString(firstLine); match != "" {
		tool.Version = match
	}
	return tool
}
