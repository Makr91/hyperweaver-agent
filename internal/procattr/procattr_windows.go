package procattr

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// NoConsole returns process attributes that prevent Windows from allocating
// a console window for a console-subsystem child. GUI children are
// unaffected — CREATE_NO_WINDOW only suppresses console creation, it never
// hides a child's own windows (so a configured browser still appears).
func NoConsole() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}
