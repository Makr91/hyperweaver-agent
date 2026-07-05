// Package hostinfo reports the host environment shown in SHI's footer:
// OS name, architecture, CPU count, and total memory. Per-OS lookups live in
// the _windows/_linux/_darwin files; everything is CGO-free.
package hostinfo

import (
	"runtime"
	"sync"
)

// Info describes the host machine.
type Info struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	CPUs        int    `json:"cpus"`
	MemoryBytes uint64 `json:"memory_bytes"`
}

var (
	once   sync.Once
	cached Info
)

// Get returns the host description. Values cannot change while the process
// runs, so the probe happens once.
func Get() Info {
	once.Do(func() {
		cached = Info{
			OS:          osName(),
			Arch:        runtime.GOARCH,
			CPUs:        runtime.NumCPU(),
			MemoryBytes: totalMemory(),
		}
	})
	return cached
}
