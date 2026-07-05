package hostinfo

import (
	"golang.org/x/sys/unix"
)

// osName combines the product name and version macOS reports via sysctl
// (e.g. "macOS 15.5").
func osName() string {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil || version == "" {
		return "macOS"
	}
	return "macOS " + version
}

// totalMemory reads the installed RAM via sysctl.
func totalMemory() uint64 {
	memory, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0
	}
	return memory
}
