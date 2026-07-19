// Package utm shells out to utmctl and osascript for UTM machine queries on
// macOS — internal/vbox's twin for the second hypervisor backend. Lifecycle
// verbs ride utmctl (callers supply the path from the prerequisite detector;
// /Applications/UTM.app/Contents/MacOS/utmctl when not on PATH);
// configuration rides UTM's AppleScript/JXA scripting API through embedded
// scripts. Config updates require the machine stopped — UTM refuses them
// otherwise.
package utm

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// ErrNotFound reports that UTM has no machine registered under the requested
// identifier.
var ErrNotFound = errors.New("machine not found in UTM")

//go:embed scripts/list_vms.js
var listVMsScript []byte

// runUtmctl executes a short-lived utmctl command, folding stderr into the
// returned error. utmctl's failure modes go beyond exit codes: exit 126
// means the binary itself was not found/executable, and stderr carrying
// "Error" or "OSStatus error" at exit 0 still means failure.
func runUtmctl(ctx context.Context, utmctlPath string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, utmctlPath, args...)
	cmd.SysProcAttr = procattr.NoConsole()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	detail := strings.TrimSpace(stderr.String())
	// utmctl's exact unknown-id stderr text is undocumented in every reference
	// read, so failures surface verbatim rather than mapping to ErrNotFound —
	// the dispatch layer wires the sentinel once the text is observed on a
	// live Mac.
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 126 {
			return "", fmt.Errorf("utmctl %s: utmctl not found at %s: %w", args[0], utmctlPath, err)
		}
		if detail != "" {
			return "", fmt.Errorf("utmctl %s: %w: %s", args[0], err, detail)
		}
		return "", fmt.Errorf("utmctl %s: %w", args[0], err)
	}
	if strings.Contains(detail, "Error") || strings.Contains(detail, "OSStatus error") {
		return "", fmt.Errorf("utmctl %s: %s", args[0], detail)
	}
	return stdout.String(), nil
}

// runOSA materializes an embedded script to a temp file and executes it via
// osascript (lang "JavaScript" adds -l JavaScript; anything else runs as
// AppleScript). AppleScript `log` output arrives on STDERR, so the answer is
// stdout when non-empty, else stderr — that is where the read scripts speak.
func runOSA(ctx context.Context, script []byte, lang string, args ...string) (string, error) {
	suffix := ".applescript"
	if lang == "JavaScript" {
		suffix = ".js"
	}
	tmp, err := os.CreateTemp("", "utm-*"+suffix)
	if err != nil {
		return "", fmt.Errorf("osascript: stage script: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, werr := tmp.Write(script); werr != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("osascript: stage script: %w", werr)
	}
	if cerr := tmp.Close(); cerr != nil {
		return "", fmt.Errorf("osascript: stage script: %w", cerr)
	}

	osaArgs := []string{}
	if lang == "JavaScript" {
		osaArgs = append(osaArgs, "-l", "JavaScript")
	}
	osaArgs = append(osaArgs, tmp.Name())
	osaArgs = append(osaArgs, args...)

	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", osaArgs...)
	cmd.SysProcAttr = procattr.NoConsole()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if rerr := cmd.Run(); rerr != nil {
		detail := strings.TrimSpace(stderr.String())
		if strings.Contains(detail, "get virtual machine id") {
			return "", ErrNotFound
		}
		if detail != "" {
			return "", fmt.Errorf("osascript: %w: %s", rerr, detail)
		}
		return "", fmt.Errorf("osascript: %w", rerr)
	}
	if out := strings.TrimSpace(stdout.String()); out != "" {
		return out, nil
	}
	return strings.TrimSpace(stderr.String()), nil
}

// Registered is one entry of the scripting-API machine list.
type Registered struct {
	Name   string `json:"Name"`
	UUID   string `json:"UUID"`
	Status string `json:"Status"`
}

// List returns every machine UTM knows, via the JXA list script (utmctl's
// own list output parses worse).
func List(ctx context.Context) ([]Registered, error) {
	out, err := runOSA(ctx, listVMsScript, "JavaScript")
	if err != nil {
		return nil, fmt.Errorf("UTM list: %w", err)
	}
	regs := []Registered{}
	if uerr := json.Unmarshal([]byte(out), &regs); uerr != nil {
		return nil, fmt.Errorf("UTM list: %w", uerr)
	}
	return regs, nil
}

// Status returns a machine's raw UTM state (starting|started|paused|stopped
// — UTM has no "running" state; started is it).
func Status(ctx context.Context, utmctlPath, id string) (string, error) {
	out, err := runUtmctl(ctx, utmctlPath, "status", id)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Start boots a machine.
func Start(ctx context.Context, utmctlPath, id string) error {
	_, err := runUtmctl(ctx, utmctlPath, "start", id)
	return err
}

// Stop shuts a machine down; force pulls the plug. Paused machines must
// resume before stop takes — the caller owns that rung of the ladder.
func Stop(ctx context.Context, utmctlPath, id string, force bool) error {
	args := []string{"stop", id}
	if force {
		args = append(args, "--force")
	}
	_, err := runUtmctl(ctx, utmctlPath, args...)
	return err
}

// Suspend pauses a machine.
func Suspend(ctx context.Context, utmctlPath, id string) error {
	_, err := runUtmctl(ctx, utmctlPath, "suspend", id)
	return err
}

// Delete removes a machine from UTM, bundle included.
func Delete(ctx context.Context, utmctlPath, id string) error {
	_, err := runUtmctl(ctx, utmctlPath, "delete", id)
	return err
}

// Exec runs a command inside the guest through the qemu-guest-agent
// (`utmctl exec <id> --cmd ...`) and returns its output.
func Exec(ctx context.Context, utmctlPath, id string, command ...string) (string, error) {
	args := append([]string{"exec", id, "--cmd"}, command...)
	return runUtmctl(ctx, utmctlPath, args...)
}

// GuestIPs returns the guest's IP addresses (`utmctl ip-address` — needs the
// qemu-guest-agent running in the guest).
func GuestIPs(ctx context.Context, utmctlPath, id string) ([]string, error) {
	out, err := runUtmctl(ctx, utmctlPath, "ip-address", id)
	if err != nil {
		return nil, err
	}
	ips := []string{}
	for _, line := range strings.Split(out, "\n") {
		if ip := strings.TrimSpace(line); ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Version reads UTM's version through System Events — the one probe that
// answers without launching UTM's scripting interface.
func Version(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", "-e",
		`tell application "System Events" to return version of application "UTM"`)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("UTM version: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("UTM version: %w", err)
	}
	version := strings.TrimSpace(string(out))
	if version == "" || strings.Contains(version, "get application") {
		return "", errors.New("UTM version: UTM not detected")
	}
	return version, nil
}

// VersionSupported reports whether a UTM version meets the 4.6.5 floor
// (import + registry support arrived there).
func VersionSupported(version string) bool {
	floor := [3]int{4, 6, 5}
	parts := strings.Split(strings.TrimSpace(version), ".")
	for i := 0; i < len(floor); i++ {
		n := 0
		if i < len(parts) {
			v, err := strconv.Atoi(strings.TrimSpace(parts[i]))
			if err != nil {
				return false
			}
			n = v
		}
		if n != floor[i] {
			return n > floor[i]
		}
	}
	return true
}

// MapUTMState translates a raw UTM status into the agent's machine-state
// vocabulary: started→running, stopped→stopped, paused→paused,
// starting→starting, anything else→unknown.
func MapUTMState(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "started":
		return "running"
	case "stopped":
		return "stopped"
	case "paused":
		return "paused"
	case "starting":
		return "starting"
	default:
		return "unknown"
	}
}

// RandomMAC generates a locally-administered MAC address — UTM cannot
// generate one through scripting, so the first byte gets the local bit
// ((b&0xFC)|0x02) and the rest are random.
func RandomMAC() string {
	b := make([]byte, 6)
	// crypto/rand.Read never returns an error and always fills b (the Go
	// library contract).
	_, _ = rand.Read(b)
	b[0] = (b[0] & 0xFC) | 0x02
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}
