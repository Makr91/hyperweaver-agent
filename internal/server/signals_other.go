//go:build !windows

package server

import "syscall"

// signalByName maps the Agent API signal vocabulary (the Node agent's
// allowed set) to the platform signal.
func signalByName(name string) (syscall.Signal, bool) {
	switch name {
	case "TERM":
		return syscall.SIGTERM, true
	case "KILL":
		return syscall.SIGKILL, true
	case "HUP":
		return syscall.SIGHUP, true
	case "INT":
		return syscall.SIGINT, true
	case "USR1":
		return syscall.SIGUSR1, true
	case "USR2":
		return syscall.SIGUSR2, true
	case "STOP":
		return syscall.SIGSTOP, true
	case "CONT":
		return syscall.SIGCONT, true
	default:
		return 0, false
	}
}
