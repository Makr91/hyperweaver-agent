package server

import "syscall"

// signalByName maps the Agent API signal vocabulary to what this platform
// can actually deliver. Windows has no POSIX signals — gopsutil implements
// TERM and KILL via TerminateProcess; everything else is honestly
// unsupported (400, never a silent no-op).
func signalByName(name string) (syscall.Signal, bool) {
	switch name {
	case "TERM":
		return syscall.SIGTERM, true
	case "KILL":
		return syscall.SIGKILL, true
	default:
		return 0, false
	}
}
