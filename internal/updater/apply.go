package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The apply flow (Mark's ruling 2026-07-06, SHI's download-then-relaunch):
// download this platform's installer from the release, verify it against the
// release's SHA256SUMS.txt — verification is mandatory, an unverifiable
// installer never launches — start it, and exit the agent so the installer
// can replace the binary (the Windows installer also closes the app itself,
// CloseApplications=yes).

// OpApply is the agent-update task operation (category system).
const OpApply = "agent_update"

// PlatformAssetURL picks this platform's installer URL from the versioninfo
// document ("" when the document carries none for this OS).
func (i *Info) PlatformAssetURL() string {
	switch runtime.GOOS {
	case "windows":
		return i.WindowsURL
	case "darwin":
		return i.MacOSURL
	default:
		return i.LinuxURL
	}
}

// ApplyEnv wires the update executor.
type ApplyEnv struct {
	VersionInfoURL string
	CurrentVersion string
	// DownloadsDir receives the installer (SHI's downloads directory).
	DownloadsDir string
	// ExitAgent triggers the agent's clean exit once the installer launched.
	ExitAgent func()
}

// RegisterExecutors wires the agent-update operation into the task queue.
func RegisterExecutors(queue *tasks.Queue, env *ApplyEnv) {
	e := &applyExecutor{env: env}
	queue.Register(OpApply, tasks.Executor{Run: e.apply})
}

type applyExecutor struct {
	env *ApplyEnv
}

// apply executes one agent_update task end to end.
func (e *applyExecutor) apply(ctx context.Context, _ *tasks.Task, out *tasks.OutputWriter) error {
	if e.env.VersionInfoURL == "" {
		return errors.New("update checking is not configured (updates.versioninfo_url)")
	}
	info, available, err := Check(ctx, e.env.VersionInfoURL, e.env.CurrentVersion)
	if err != nil {
		return err
	}
	if !available {
		return fmt.Errorf("already up to date (%s)", e.env.CurrentVersion)
	}

	assetURL := info.PlatformAssetURL()
	if assetURL == "" {
		return errors.New("the versioninfo document carries no installer URL for this platform")
	}
	parsed, err := url.Parse(assetURL)
	if err != nil {
		return fmt.Errorf("installer URL: %w", err)
	}
	filename := path.Base(parsed.Path)

	// Verification is not optional: the checksum must exist before a byte
	// downloads.
	expected, err := fetchChecksum(ctx, info.ChecksumsURL, filename)
	if err != nil {
		return err
	}

	if merr := os.MkdirAll(e.env.DownloadsDir, 0o700); merr != nil {
		return merr
	}
	target, err := safepath.Under(e.env.DownloadsDir, filename)
	if err != nil {
		return err
	}

	out.Write("stdout", "Downloading "+assetURL+"\n")
	sha, err := downloadTo(ctx, assetURL, target)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sha, expected) {
		_ = os.Remove(target)
		return fmt.Errorf("installer hash mismatch: downloaded %s, SHA256SUMS says %s — file discarded", sha, expected)
	}
	out.Write("stdout", "Installer verified ("+sha+")\n")

	if lerr := launchInstaller(target, out); lerr != nil {
		return lerr
	}
	out.Write("stdout", "Update "+info.Version+" launched — the agent is exiting so the installer can replace it\n")
	e.env.ExitAgent()
	return nil
}

// fetchChecksum reads the release's SHA256SUMS.txt and returns filename's
// digest.
func fetchChecksum(ctx context.Context, checksumsURL, filename string) (string, error) {
	if checksumsURL == "" {
		return "", errors.New("the versioninfo document carries no checksumsUrl — refusing an unverifiable update")
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, checksumsURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checksums fetch returned %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && fields[1] == filename {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("SHA256SUMS.txt has no entry for %s", filename)
}

// downloadTo streams the URL to target through the shared writer, returning
// the stream's SHA-256.
func downloadTo(ctx context.Context, assetURL, target string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("installer download returned %s", resp.Status)
	}

	hasher := sha256.New()
	// 0o700: the Windows installer is executed directly; harmless elsewhere.
	if _, werr := safepath.WriteFileFrom(target, io.TeeReader(resp.Body, hasher), 0o700); werr != nil {
		return "", werr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// launchInstaller starts the platform installer detached from the agent (its
// lifetime must outlive ours): the .exe directly on Windows, `open` for the
// macOS .pkg, xdg-open for the Linux .deb — and on a headless Linux box
// without xdg-open, the download is kept and the operator finishes with dpkg.
func launchInstaller(target string, out *tasks.OutputWriter) error {
	// Deliberately NOT the task context: cancelling the task must never kill
	// a running installer.
	launchCtx := context.Background()

	switch runtime.GOOS {
	case "windows":
		exe, err := safepath.ValidateExecutable(target)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(launchCtx, exe)
		cmd.SysProcAttr = procattr.NoConsole()
		return cmd.Start()
	case "darwin":
		cmd := exec.CommandContext(launchCtx, "/usr/bin/open", target)
		return cmd.Start()
	default:
		// Best-effort on Linux: without xdg-open (headless boxes) the
		// download is kept and the operator finishes with dpkg.
		if opener, lerr := exec.LookPath("xdg-open"); lerr == nil {
			cmd := exec.CommandContext(launchCtx, opener, target)
			return cmd.Start()
		}
		out.Write("stderr", "xdg-open not available — install manually: sudo dpkg -i "+target+"\n")
		return nil
	}
}
