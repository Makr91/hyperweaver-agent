// Package prereqs detects the external tools the provisioning engine drives
// (Vagrant, VirtualBox, Git) — SHI parity: presence + version display.
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

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
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
		probePath(probeCtx, "git", lookPath("git"), "--version"),
	}

	cached = tools
	cachedAt = time.Now()

	out := make([]Tool, len(tools))
	copy(out, tools)
	return out
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
	out, err := exec.CommandContext(ctx, exe, args...).Output()
	if err != nil {
		return tool
	}

	firstLine := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if match := versionPattern.FindString(firstLine); match != "" {
		tool.Version = match
	}
	return tool
}
