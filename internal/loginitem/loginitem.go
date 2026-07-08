// Package loginitem registers (or removes) the agent as a start-at-login
// item using each OS's native mechanism: the HKCU Run key on Windows, a
// LaunchAgent plist on macOS, an XDG autostart .desktop entry on Linux.
// Headless server installs boot via their service manager (systemd unit in
// the packaging) — this package is the DESKTOP login story
// (startup.start_at_login).
package loginitem

import (
	"fmt"
	"os"
	"strings"
)

// Sync converges the login item onto the configured state: enabled registers
// the running executable (with args) to start at login; disabled removes the
// registration. Errors never stop the agent — the caller logs and continues.
func Sync(enabled bool, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	if enabled {
		return register(exe, args)
	}
	return unregister()
}

// commandLine renders the executable + args as one quoted command line.
func commandLine(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteArg(exe))
	for _, arg := range args {
		parts = append(parts, quoteArg(arg))
	}
	return strings.Join(parts, " ")
}

func quoteArg(arg string) string {
	if strings.ContainsAny(arg, " \t") {
		return `"` + arg + `"`
	}
	return arg
}
