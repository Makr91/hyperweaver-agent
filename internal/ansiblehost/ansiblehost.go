// Package ansiblehost resolves the agent host's ansible control node: the
// native binaries where the OS carries them, and on Windows — where ansible
// has no native control-node support — the default WSL distribution's ansible
// (the transports matrix's WSL rows). Callers build invocations through a
// Runner so the same argument set runs natively or wrapped in `wsl.exe -e sh
// -c` with host paths translated to their /mnt form.
package ansiblehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// Runner builds host-ansible invocations. A zero wslExe means native.
type Runner struct {
	wslExe string
}

// Invocation is one ready-to-exec host command. Env nil inherits the parent
// environment (runHostCommand's contract).
type Invocation struct {
	Exe  string
	Args []string
	Env  []string
}

// Resolve answers a Runner able to run the named ansible tool, or an error
// when the host has no control node for it.
func Resolve(ctx context.Context, tool string) (*Runner, error) {
	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, err
		}
		return &Runner{}, nil
	}
	wslExe, ok, _ := wslProbe(ctx)
	if !ok {
		return nil, errors.New("no WSL ansible control node — install WSL and ansible inside its default distribution")
	}
	return &Runner{wslExe: wslExe}, nil
}

// WSL reports whether invocations wrap through the WSL control node.
func (r *Runner) WSL() bool {
	return r.wslExe != ""
}

// Has reports whether the named companion tool is runnable — WSL probes found
// the toolchain whole; native asks PATH.
func (r *Runner) Has(tool string) bool {
	if r.WSL() {
		return true
	}
	_, err := exec.LookPath(tool)
	return err == nil
}

// Path renders one host path for ansible's own arguments — identity natively,
// the /mnt translation under WSL.
func (r *Runner) Path(p string) string {
	if !r.WSL() {
		return p
	}
	return windowsToWSL(p)
}

// PathList joins host paths into a list value with the control node's own
// separator.
func (r *Runner) PathList(paths ...string) string {
	if !r.WSL() {
		return strings.Join(paths, string(os.PathListSeparator))
	}
	translated := make([]string, 0, len(paths))
	for _, p := range paths {
		translated = append(translated, windowsToWSL(p))
	}
	return strings.Join(translated, ":")
}

// DevNull is the control node's null device.
func (r *Runner) DevNull() string {
	if !r.WSL() {
		return os.DevNull
	}
	return "/dev/null"
}

// RelPath renders a document-relative slash path for the control node.
func (r *Runner) RelPath(p string) string {
	if !r.WSL() {
		return filepath.FromSlash(p)
	}
	return path.Clean(filepath.ToSlash(p))
}

// Invocation builds one tool run: env entries ride the process environment
// natively and export inside the wrapped command under WSL; keyPath, when
// set, lands as --private-key — under WSL through a chmod-600 mktemp copy,
// because keys on /mnt mounts are world-readable and OpenSSH refuses them.
func (r *Runner) Invocation(tool string, env map[string]string, keyPath string, args ...string) (*Invocation, error) {
	if !r.WSL() {
		exe, err := exec.LookPath(tool)
		if err != nil {
			return nil, err
		}
		full := append([]string{}, args...)
		if keyPath != "" {
			full = append(full, "--private-key", keyPath)
		}
		var entries []string
		if len(env) > 0 {
			entries = append(entries, os.Environ()...)
			for _, key := range sortedKeys(env) {
				entries = append(entries, key+"="+env[key])
			}
		}
		return &Invocation{Exe: exe, Args: full, Env: entries}, nil
	}

	var b strings.Builder
	for _, key := range sortedKeys(env) {
		b.WriteString("export " + key + "=" + shq(env[key]) + "; ")
	}
	if keyPath != "" {
		b.WriteString(`hwkey=$(mktemp); cp ` + shq(windowsToWSL(keyPath)) + ` "$hwkey"; chmod 600 "$hwkey"; `)
	}
	b.WriteString(tool)
	for _, arg := range args {
		b.WriteString(" ")
		b.WriteString(shq(arg))
	}
	if keyPath != "" {
		b.WriteString(` --private-key "$hwkey"; hwrc=$?; rm -f "$hwkey"; exit $hwrc`)
	}
	return &Invocation{Exe: r.wslExe, Args: []string{"-e", "sh", "-c", b.String()}}, nil
}

// DetectWSL probes the Windows host's WSL control node for the prereqs
// surface: installed, the ansible core version, and the wsl.exe path carrying
// it.
func DetectWSL(ctx context.Context) (installed bool, version, wslPath string) {
	exe, ok, ver := wslProbe(ctx)
	return ok, ver, exe
}

var versionPattern = regexp.MustCompile(`\d+\.\d+[\w.\-]*`)

const probeTTL = time.Minute

var (
	probeMu      sync.Mutex
	probedAt     time.Time
	probeExe     string
	probeOK      bool
	probeVersion string
)

// wslProbe locates wsl.exe and proves ansible-playbook inside the default
// distribution, caching the answer — a cold distro start costs seconds.
func wslProbe(ctx context.Context) (exe string, ok bool, version string) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if !probedAt.IsZero() && time.Since(probedAt) < probeTTL {
		return probeExe, probeOK, probeVersion
	}
	probedAt = time.Now()
	probeExe, probeOK, probeVersion = "", false, ""

	wslExe, err := exec.LookPath("wsl.exe")
	if err != nil {
		return probeExe, probeOK, probeVersion
	}
	cmd := exec.CommandContext(ctx, wslExe, "-e", "sh", "-c",
		"command -v ansible-playbook >/dev/null 2>&1 && ansible --version")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return probeExe, probeOK, probeVersion
	}
	probeExe, probeOK = wslExe, true
	firstLine := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	probeVersion = versionPattern.FindString(firstLine)
	return probeExe, probeOK, probeVersion
}

var (
	hostIPMu  sync.Mutex
	hostIPAt  time.Time
	hostIPVal string
	hostIPErr error
)

// WSLHostIP answers the Windows host's address as the WSL distribution sees
// it — the default-route gateway (the host-internal vEthernet (WSL) adapter;
// NAT-mode WSL2 shares no loopback with the host, so 127.0.0.1 targets never
// leave the distribution). Cached briefly — the address changes per Windows
// boot, never mid-run.
func WSLHostIP(ctx context.Context) (string, error) {
	hostIPMu.Lock()
	defer hostIPMu.Unlock()
	if !hostIPAt.IsZero() && time.Since(hostIPAt) < probeTTL {
		return hostIPVal, hostIPErr
	}
	hostIPAt = time.Now()
	hostIPVal, hostIPErr = "", nil

	wslExe, err := exec.LookPath("wsl.exe")
	if err != nil {
		hostIPErr = err
		return hostIPVal, hostIPErr
	}
	cmd := exec.CommandContext(ctx, wslExe, "-e", "sh", "-c", "ip route show default")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		hostIPErr = fmt.Errorf("resolve the WSL default route: %w", err)
		return hostIPVal, hostIPErr
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" && fields[1] == "via" {
			hostIPVal = fields[2]
			return hostIPVal, nil
		}
	}
	hostIPErr = errors.New("the WSL distribution reports no default route")
	return hostIPVal, hostIPErr
}

// windowsToWSL maps a drive path onto its /mnt form; drive-less paths keep
// their shape with slashes flipped.
func windowsToWSL(p string) string {
	p = filepath.Clean(p)
	if len(p) >= 2 && p[1] == ':' &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		return "/mnt/" + strings.ToLower(p[:1]) + filepath.ToSlash(p[2:])
	}
	return filepath.ToSlash(p)
}

// shq single-quotes one value for the wrapped sh command.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
