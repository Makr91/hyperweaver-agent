package hostinfo

import (
	"os"
	"strconv"
	"strings"
)

// osName reads PRETTY_NAME from os-release (e.g. "Debian GNU/Linux 13").
// Both locations are compile-time literals.
func osName() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		raw, err = os.ReadFile("/usr/lib/os-release")
	}
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if value, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return "Linux"
}

// totalMemory reads MemTotal from /proc/meminfo (reported in kB).
func totalMemory() uint64 {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		value, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return 0
		}
		kilobytes, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return kilobytes * 1024
	}
	return 0
}
