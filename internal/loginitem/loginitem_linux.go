package loginitem

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// Linux: an XDG autostart .desktop entry — desktop sessions start the agent
// at login. Headless installs boot via the packaged systemd unit instead.

func autostartPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "autostart", "hyperweaver-agent.desktop"), nil
}

func register(exe string, args []string) error {
	path, err := autostartPath()
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(filepath.Dir(path), 0o750); merr != nil {
		return merr
	}
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=Hyperweaver Agent
Comment=Hyperweaver Agent (start at login)
Exec=%s
X-GNOME-Autostart-enabled=true
`, commandLine(exe, args))
	// 0600 suffices: the user's own session manager reads it.
	return safepath.WriteFile(path, []byte(entry), 0o600)
}

func unregister() error {
	path, err := autostartPath()
	if err != nil {
		return err
	}
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return rerr
	}
	return nil
}
