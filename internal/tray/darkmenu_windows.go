//go:build windows

package tray

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// enableDarkMenus opts the process's classic Win32 popup menus into the OS
// app theme — the tray menu is a TrackPopupMenu menu, which Windows never
// dark-themes on its own (dark-menued native apps all ride uxtheme's
// undocumented-but-stable pair: SetPreferredAppMode ordinal 135 +
// FlushMenuThemes ordinal 136, Windows 10 1809+). AllowDark (1) FOLLOWS the
// user's light/dark choice rather than forcing either; absent ordinals
// (older Windows) leave the menus light.
func enableDarkMenus() {
	uxtheme, err := windows.LoadLibraryEx("uxtheme.dll", 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return
	}
	setPreferredAppMode, err := windows.GetProcAddressByOrdinal(uxtheme, 135)
	if err != nil {
		return
	}
	const allowDark = 1
	_, _, _ = syscall.SyscallN(setPreferredAppMode, allowDark)
	if flushMenuThemes, ferr := windows.GetProcAddressByOrdinal(uxtheme, 136); ferr == nil {
		_, _, _ = syscall.SyscallN(flushMenuThemes)
	}
}
