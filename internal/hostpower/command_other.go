//go:build !windows

package hostpower

import "strconv"

// shutdownBinary is the Unix shutdown command (Linux and macOS both ship
// it; on systemd hosts it is the systemctl shim). The agent must run with
// the privilege to call it — a permission refusal fails the task with the
// command's own error, honestly.
const shutdownBinary = "shutdown"

// commandArgs builds Unix shutdown arguments. The grace period converts to
// shutdown's minute granularity (rounded up; 0 = now). -h halts/powers off
// on both Linux (systemd maps it to poweroff) and macOS.
func commandArgs(operation string, meta Metadata) []string {
	when := "now"
	if meta.GracePeriod > 0 {
		minutes := (meta.GracePeriod + 59) / 60
		when = "+" + strconv.Itoa(minutes)
	}
	var args []string
	switch operation {
	case OpRestart:
		args = []string{"-r", when}
	case OpHalt:
		args = []string{"-h", "now"}
	default: // shutdown, poweroff
		args = []string{"-h", when}
	}
	if meta.Message != "" && operation != OpHalt {
		args = append(args, meta.Message)
	}
	return args
}
