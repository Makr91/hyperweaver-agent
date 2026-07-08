//go:build darwin

package keepawake

import (
	"fmt"

	"github.com/ebitengine/purego"
)

// IOKit power-assertion constants (IOPMLib.h / CFString.h).
const (
	kIOPMAssertionLevelOn      = 255
	kCFStringEncodingUTF8      = 0x08000100
	preventUserIdleSystemSleep = "PreventUserIdleSystemSleep"
)

// acquire creates an IOKit power assertion — IOPMAssertionCreateWithName
// (kIOPMAssertionTypePreventUserIdleSystemSleep), the exact assertion Apple's
// own caffeinate -i takes — called directly through purego's dlopen bindings:
// native API, no cgo toolchain, no child process (Mark's ruling 2026-07-07).
// The assertion shows up in `pmset -g assertions` under the reason string and
// dies with the process.
func acquire(reason string) (func(), error) {
	coreFoundation, err := purego.Dlopen(
		"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
		purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("load CoreFoundation: %w", err)
	}
	iokit, err := purego.Dlopen(
		"/System/Library/Frameworks/IOKit.framework/IOKit",
		purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("load IOKit: %w", err)
	}

	var cfStringCreateWithCString func(alloc uintptr, value string, encoding uint32) uintptr
	purego.RegisterLibFunc(&cfStringCreateWithCString, coreFoundation, "CFStringCreateWithCString")
	var assertionCreateWithName func(assertionType uintptr, level uint32, name uintptr, id *uint32) int32
	purego.RegisterLibFunc(&assertionCreateWithName, iokit, "IOPMAssertionCreateWithName")
	var assertionRelease func(id uint32) int32
	purego.RegisterLibFunc(&assertionRelease, iokit, "IOPMAssertionRelease")

	assertionType := cfStringCreateWithCString(0, preventUserIdleSystemSleep, kCFStringEncodingUTF8)
	reasonRef := cfStringCreateWithCString(0, reason, kCFStringEncodingUTF8)
	if assertionType == 0 || reasonRef == 0 {
		return nil, fmt.Errorf("CFStringCreateWithCString failed")
	}

	var id uint32
	if ret := assertionCreateWithName(assertionType, kIOPMAssertionLevelOn, reasonRef, &id); ret != 0 {
		return nil, fmt.Errorf("IOPMAssertionCreateWithName returned 0x%x", uint32(ret))
	}
	return func() {
		_ = assertionRelease(id)
	}, nil
}
