package hostpower

import "strconv"

// shutdownBinary is Windows' shutdown.exe (resolved via PATH — always
// present in System32, which is on the system PATH).
const shutdownBinary = "shutdown"

// commandArgs builds shutdown.exe arguments. Windows makes no
// shutdown/poweroff distinction (/s powers the machine off); halt is the
// immediate no-grace form.
func commandArgs(operation string, meta Metadata) []string {
	grace := strconv.Itoa(meta.GracePeriod)
	var args []string
	switch operation {
	case OpRestart:
		args = []string{"/r", "/t", grace}
	case OpHalt:
		args = []string{"/s", "/t", "0", "/f"}
	default: // shutdown, poweroff
		args = []string{"/s", "/t", grace}
	}
	if meta.Message != "" && operation != OpHalt {
		args = append(args, "/c", meta.Message)
	}
	return args
}
