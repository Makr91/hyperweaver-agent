package loginitem

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// macOS: a per-user LaunchAgent — launchd starts the agent at login;
// RunAtLoad only (no KeepAlive: the tray Quit must stick).
const launchAgentLabel = "com.startcloud.hyperweaver-agent"

func launchAgentPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchAgentLabel+".plist"), nil
}

func register(exe string, args []string) error {
	path, err := launchAgentPath()
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(filepath.Dir(path), 0o750); merr != nil {
		return merr
	}
	arguments := &strings.Builder{}
	for _, arg := range append([]string{exe}, args...) {
		fmt.Fprintf(arguments, "    <string>%s</string>\n", xmlEscape(arg))
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>%s</string>
  <key>ProgramArguments</key>
  <array>
%s  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
`, launchAgentLabel, arguments.String())
	// 0600 suffices: the per-user launchd reads LaunchAgents as this user.
	return safepath.WriteFile(path, []byte(plist), 0o600)
}

func unregister() error {
	path, err := launchAgentPath()
	if err != nil {
		return err
	}
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return rerr
	}
	return nil
}

func xmlEscape(s string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(s)
}
