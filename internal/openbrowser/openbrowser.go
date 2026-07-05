// Package openbrowser launches the agent's web UI in a browser: the
// configured browser.path when set, otherwise the system default browser.
package openbrowser

import (
	"context"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cli/browser"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Open launches url. browserPath optionally names a specific browser
// executable (or a .app bundle on macOS); empty uses the system default.
// The configured path is settable through the settings API, so it is treated
// as untrusted and validated before anything is spawned.
func Open(url, browserPath string) {
	if browserPath == "" {
		if err := browser.OpenURL(url); err != nil {
			slog.Error("open default browser", "url", url, "error", err)
		}
		return
	}

	// Background context: the browser is a fire-and-forget user process, not
	// a request-scoped child.
	ctx := context.Background()
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" && strings.HasSuffix(browserPath, ".app") {
		bundle, err := safepath.ValidateAppBundle(browserPath)
		if err != nil {
			slog.Error("configured browser is not a valid app bundle", "browser", browserPath, "error", err)
			return
		}
		cmd = exec.CommandContext(ctx, "open", "-a", bundle, url)
	} else {
		exe, err := safepath.ValidateExecutable(browserPath)
		if err != nil {
			slog.Error("configured browser is not a valid executable", "browser", browserPath, "error", err)
			return
		}
		cmd = exec.CommandContext(ctx, exe, url)
	}

	if err := cmd.Start(); err != nil {
		slog.Error("open configured browser", "browser", browserPath, "url", url, "error", err)
		return
	}
	// Detach: the browser process outlives the click handler.
	go func() {
		if err := cmd.Wait(); err != nil {
			slog.Warn("configured browser exited with error", "browser", browserPath, "error", err)
		}
	}()
}
