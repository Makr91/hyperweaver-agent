//go:build !windows

package procattr

import "syscall"

// NoConsole is a no-op outside Windows: consoles are a Windows-subsystem
// concept; Unix children never pop terminal windows.
func NoConsole() *syscall.SysProcAttr {
	return nil
}
