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
)

// Open launches url. browserPath optionally names a specific browser
// executable (or a .app bundle on macOS); empty uses the system default.
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
		cmd = exec.CommandContext(ctx, "open", "-a", browserPath, url) // #nosec G204 -- browserPath is the user's own configured browser
	} else {
		cmd = exec.CommandContext(ctx, browserPath, url) // #nosec G204 -- browserPath is the user's own configured browser
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
