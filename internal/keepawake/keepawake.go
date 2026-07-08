// Package keepawake holds a system-wide sleep inhibition while the agent
// runs (host_power.prevent_sleep — SHI's preventsystemfromsleep preference,
// implemented with each OS's native power-management API; Mark's ruling
// 2026-07-07: no spawned helper processes, no cgo). The inhibition covers
// SYSTEM sleep only — the display may still sleep and lock; virtual machines
// do not need the screen on.
package keepawake

// Acquire asks the operating system to keep the host awake. The returned
// release function undoes it; every mechanism also releases automatically
// when the process exits, so a crash never leaves the host insomniac.
func Acquire(reason string) (release func(), err error) {
	return acquire(reason)
}
