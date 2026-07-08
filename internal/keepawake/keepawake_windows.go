//go:build windows

package keepawake

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// SetThreadExecutionState flags (winbase.h).
const (
	esContinuous     = 0x80000000
	esSystemRequired = 0x00000001
)

// acquire calls SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) —
// the Win32 keep-awake API (the same family SDL/SHI's screensaver suspension
// rides, with the SYSTEM flag instead of DISPLAY: the host must not sleep,
// the screen may). The state is per-THREAD, so a dedicated goroutine locks
// itself to one OS thread and parks there holding the flag until release —
// an unlocked goroutine migrates threads and the flag would die with the
// thread the scheduler recycles.
func acquire(_ string) (func(), error) {
	setThreadExecutionState := windows.NewLazySystemDLL("kernel32.dll").
		NewProc("SetThreadExecutionState")

	acquired := make(chan error, 1)
	done := make(chan struct{})
	released := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ret, _, callErr := setThreadExecutionState.Call(uintptr(esContinuous | esSystemRequired))
		if ret == 0 {
			acquired <- fmt.Errorf("SetThreadExecutionState: %w", callErr)
			return
		}
		acquired <- nil
		<-done
		// Clearing back to ES_CONTINUOUS alone restores normal power management.
		_, _, _ = setThreadExecutionState.Call(uintptr(esContinuous))
		close(released)
	}()
	if err := <-acquired; err != nil {
		return nil, err
	}
	return func() {
		close(done)
		<-released
	}, nil
}
