//go:build linux

package keepawake

import (
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
)

// acquire takes a systemd-logind sleep inhibitor over D-Bus —
// org.freedesktop.login1.Manager.Inhibit("sleep:idle", …, "block"), the same
// call systemd-inhibit(1) wraps, held as a file descriptor and released by
// closing it (or by process exit). No helper process (Mark's ruling
// 2026-07-07). Visible in `systemd-inhibit --list`. Hosts without
// systemd-logind get a descriptive error; the caller logs and continues.
func acquire(reason string) (func(), error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("d-bus system bus unavailable (no systemd-logind?): %w", err)
	}

	var fd dbus.UnixFD
	logind := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	if cerr := logind.Call("org.freedesktop.login1.Manager.Inhibit", 0,
		"sleep:idle", "hyperweaver-agent", reason, "block").Store(&fd); cerr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("logind Inhibit: %w", cerr)
	}
	if fd < 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("logind Inhibit returned invalid fd %d", fd)
	}

	inhibitor := os.NewFile(uintptr(uint32(fd)), "logind-sleep-inhibitor")
	return func() {
		_ = inhibitor.Close()
		_ = conn.Close()
	}, nil
}
